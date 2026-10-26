//! LDAP Authentication plugin with optional Active Directory group filtering.
//!
//! Authenticates requests by extracting HTTP Basic credentials and validating
//! them against an LDAP directory via a bind operation. Supports two modes:
//!
//! - **Direct bind**: Uses a `bind_dn_template` with `{username}` placeholder
//!   to construct the bind DN directly. Faster, no service account needed.
//! - **Search-then-bind**: Uses a service account to search for the user's DN,
//!   then binds as that user. More flexible (supports any search filter).
//!
//! Exactly one mode may be configured, and both require
//! `canonical_identity_attribute`: the Ferrum identity is always read off the
//! directory entry that authenticated, never taken from the client-presented
//! login (which directories match case- and whitespace-insensitively).
//!
//! Optionally checks LDAP/AD group membership after authentication. When
//! `required_groups` is set, the user must belong to at least one of the
//! listed groups (OR logic) for authentication to succeed.
//!
//! Successful authentications can be cached in-memory (keyed by a random-key
//! HMAC over username + password) to avoid hitting the LDAP server on every
//! request. A cache hit skips the bind, so a password change or account
//! disablement in the directory takes effect only when the entry expires
//! (`cache_ttl_seconds`). Group membership is bounded separately: with
//! `required_groups` set, a hit whose last group check is older than
//! `group_cache_ttl_seconds` re-runs the group search before it is admitted,
//! and a user removed from every required group is refused and evicted
//! (issue #6609).
//!
//! ## TLS integration
//!
//! Both `ldaps://` and STARTTLS connections use rustls (matching the gateway's
//! TLS stack everywhere else). The plugin respects:
//! - `FERRUM_TLS_CA_BUNDLE_PATH` — custom CA bundle for verifying the LDAP
//!   server certificate. When set, the rustls trust store is built from this
//!   bundle ALONE (CA exclusivity per CLAUDE.md "TLS Architecture") — public
//!   CAs in the system / webpki bundle are NOT trusted, preventing a
//!   public-CA-issued certificate from MITM-ing the LDAP connection.
//! - `FERRUM_TLS_NO_VERIFY` — skip TLS certificate verification (testing only)
//! - `FERRUM_TLS_CRL_FILE_PATH` — gateway CRL list. When configured (and
//!   verification is not disabled), revoked LDAP server certificates are
//!   rejected via `build_server_verifier_with_crls()`, giving `ldaps://` /
//!   STARTTLS the same revocation guarantees as the proxy backend, DTLS,
//!   frontend mTLS, and rustls logging-sink surfaces.
//!
//! Every connection performs an uncached A+AAAA lookup, screens the complete
//! answer set and each imminent dial under the gateway backend egress policy,
//! and gives `ldap3` the screened socket together with the original URL. This
//! closes DNS-rebinding windows without replacing the hostname used for TLS
//! certificate and SNI verification.
//!
//! ## Availability
//!
//! Each connection splits its establishment budget across the screened
//! candidates, so one stalled replica address (TCP or TLS) cannot starve the
//! next. `failover_ldap_urls` lists further directory endpoints that are tried
//! in order when an endpoint cannot be reached or answers `busy` /
//! `unavailable`; a credential rejection never fails over.

use crate::fips::approved::HmacSha256;
use crate::fips::backend::rand::SecureRandom;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use base64::Engine;
use dashmap::DashMap;
use ldap3::{
    Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry, SearchOptions, StdStream,
    parse_filter,
};
use rustls::ClientConfig;
#[cfg(test)]
use rustls::pki_types::CertificateDer;
use rustls::pki_types::CertificateRevocationListDer;
use serde_json::Map;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::{debug, warn};
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::consumer_index::ConsumerIndex;
use crate::dns::{DnsCache, DnsConfig};
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};

use super::utils::PluginHttpClient;
use super::utils::auth_flow::{self, AuthMechanism, ExtractedCredential, VerifyOutcome};
use super::utils::header_extract::{ConfiguredHeaderLookup, lookup_configured_header};
use super::{RequestContext, strip_auth_scheme};

pub const LDAP_AUTH_DEFAULT_CACHE_TTL_SECONDS: u64 = 0;
pub const LDAP_AUTH_MAX_CACHE_TTL_SECONDS: u64 = 86_400;
/// Default bound on how long a cached authentication may be served without
/// re-checking `required_groups`.
pub const LDAP_AUTH_DEFAULT_GROUP_CACHE_TTL_SECONDS: u64 = 60;
/// A cached credential keeps authenticating for its whole TTL after the
/// password changes or the account is disabled. Above this TTL, construction
/// logs that revocation lag so it is an explicit operator choice.
pub const LDAP_AUTH_CACHE_TTL_WARN_SECONDS: u64 = 900;
pub const LDAP_AUTH_DEFAULT_MAX_CACHE_ENTRIES: usize = 10_000;
/// Upper bound on `max_cache_entries`. The cache holds one canonical identity
/// per admitted credential, so an unbounded configured maximum is a memory
/// commitment the operator cannot see; every other `ldap_auth` resource knob
/// is bounded the same way.
pub const LDAP_AUTH_MAX_CACHE_ENTRIES_LIMIT: usize = 1_000_000;
/// Upper bound on the number of `failover_ldap_urls` entries.
pub const LDAP_AUTH_MAX_FAILOVER_URLS: usize = 8;
/// Upper bound on `negative_cache_ttl_seconds`. A rejected credential is
/// remembered only briefly so a directory-side fix is not masked for long.
pub const LDAP_AUTH_MAX_NEGATIVE_CACHE_TTL_SECONDS: u64 = 300;
/// Upper bound on `max_failed_attempts_per_user`.
pub const LDAP_AUTH_MAX_FAILED_ATTEMPTS_PER_USER: u64 = 1_000;
pub const LDAP_AUTH_DEFAULT_FAILED_ATTEMPT_BACKOFF_SECONDS: u64 = 60;
pub const LDAP_AUTH_MAX_FAILED_ATTEMPT_BACKOFF_SECONDS: u64 = 3_600;
/// Upper bound on `service_connection_max_age_seconds`. Kept well below the
/// common directory idle-connection limits (Active Directory closes idle
/// connections after 900 seconds by default).
pub const LDAP_AUTH_MAX_SERVICE_CONNECTION_MAX_AGE_SECONDS: u64 = 300;
/// Active Directory `LDAP_MATCHING_RULE_IN_CHAIN`: evaluates a DN-valued link
/// attribute such as `member` transitively, so nested group membership
/// matches. Used only when `group_membership_mode` is `ad_in_chain`.
pub const LDAP_MATCHING_RULE_IN_CHAIN_OID: &str = "1.2.840.113556.1.4.1941";
/// Longest user DN or canonical identity interpolated into a group-membership
/// filter. Directory DNs are far shorter in practice; the bound keeps every
/// filter the plugin sends small regardless of what the directory returned.
const LDAP_AUTH_MAX_FILTER_VALUE_BYTES: usize = 4_096;

/// Domain-separation tags for the keyed credential digests, so a success-cache
/// key, a rejected-credential key, and a per-account key can never collide.
const CREDENTIAL_KEY_DOMAIN_SUCCESS: u8 = 1;
const CREDENTIAL_KEY_DOMAIN_REJECTED: u8 = 2;
const CREDENTIAL_KEY_DOMAIN_ACCOUNT: u8 = 3;

/// `WWW-Authenticate` challenge advertised for rejected/absent credentials.
const LDAP_AUTH_BASIC_CHALLENGE: &str = auth_flow::BASIC_AUTHENTICATION_CHALLENGE;

const LDAP_AUTH_DEFAULT_CONNECT_TIMEOUT_SECONDS: u64 = 5;
const LDAP_AUTH_MAX_CONNECT_TIMEOUT_SECONDS: u64 = 300;
const LDAP_AUTH_DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 15;
const LDAP_AUTH_MAX_REQUEST_TIMEOUT_SECONDS: u64 = 300;
const LDAP_AUTH_DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 64;
const LDAP_AUTH_MAX_CONCURRENT_REQUESTS: usize = 1_024;
const LDAP_AUTH_USER_SEARCH_SIZE_LIMIT: i32 = 2;
const LDAP_AUTH_GROUP_SEARCH_SIZE_LIMIT: i32 = 1_000;
/// RDN prefix for [`LdapAuth::equalize_unknown_user_bind`]. Each bind appends
/// 128 random bits, so no real entry can be targeted repeatedly (and locked
/// out) by unknown-username traffic.
const LDAP_AUTH_UNKNOWN_USER_EQUALIZER_RDN_PREFIX: &str = "cn=ferrum-edge-unknown-";

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct CacheKey([u8; 32]);

struct CacheEntry {
    expires_at: Instant,
    canonical_identity: String,
    /// DN of the authenticated entry, kept so a cache hit can re-run the
    /// group search without repeating the bind.
    user_dn: String,
    /// `required_groups` membership is re-checked on a hit at or after this
    /// instant.
    groups_verified_until: Instant,
    /// Distinguishes this admission from a later one under the same key, so a
    /// group re-check that raced a replacement or expiry never refreshes,
    /// admits through, or evicts an entry it did not observe.
    generation: u64,
}

/// A live cache hit.
struct CachedAuthentication {
    canonical_identity: String,
    user_dn: String,
    /// `required_groups` is configured and the last group check is older than
    /// `group_cache_ttl`.
    groups_due: bool,
    expires_at: Instant,
    generation: u64,
}

/// Result of re-checking `required_groups` for a cache hit.
enum CachedGroupRevalidation {
    Decided(VerifyOutcome),
    /// The observed entry expired or was replaced while the check ran; the
    /// caller must authenticate uncached instead of trusting it.
    Stale,
}

struct AuthenticatedUser {
    dn: String,
    canonical_identity: String,
}

/// How a group entry proves that the authenticated user is a member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GroupMembershipMode {
    /// Direct membership: `member` / `uniqueMember` hold the user DN or
    /// `memberUid` holds the canonical identity (or the configured
    /// `group_member_attribute` holds the user DN).
    Direct,
    /// Active Directory transitive membership through
    /// [`LDAP_MATCHING_RULE_IN_CHAIN_OID`] on `group_member_attribute`
    /// (default `member`).
    AdInChain,
    /// Reverse membership: the authenticated user's own entry lists group DNs
    /// in `group_member_attribute` (default `memberOf`, maintained by the
    /// directory). A required group counts only when an entry found under
    /// `group_base_dn` by its authoritative `group_attribute` value is listed
    /// there, as proven by the directory's own DN matching.
    MemberOf,
}

/// Default user-side attribute for [`GroupMembershipMode::MemberOf`].
const LDAP_AUTH_DEFAULT_MEMBER_OF_ATTRIBUTE: &str = "memberOf";

/// One directory endpoint: `ldap_url` or a `failover_ldap_urls` entry.
struct LdapEndpoint {
    /// Configured URL, handed to `ldap3` so TLS/SNI verify this hostname.
    url: String,
    /// Configured hostname retained for DNS and TLS hostname/SNI verification.
    hostname: String,
    port: u16,
    /// Service-account connection reused by searches on this endpoint while
    /// `service_connection_max_age_seconds` allows it. End-user binds never
    /// use it.
    service_connection: ArcSwapOption<PooledServiceConnection>,
}

impl LdapEndpoint {
    /// Stop handing out `retired` if it is still this endpoint's shared
    /// connection. A concurrent replacement is left in place.
    fn retire_service_connection(&self, retired: &Arc<PooledServiceConnection>) {
        // Compare-and-swap on the exact observed `Arc`: a replacement another
        // flow published after `retired` was observed is never cleared.
        let observed = Some(Arc::clone(retired));
        let _ = self.service_connection.compare_and_swap(&observed, None);
    }
}

/// A connection bound as the service account and shared by concurrent flows.
/// `ldap3` multiplexes operations over one connection, and every flow clones
/// its own handle, so per-operation options never leak between flows.
struct PooledServiceConnection {
    ldap: Ldap,
    created_at: Instant,
}

/// A service-account (or anonymous) connection lent to one flow.
///
/// Dropping a loan that was never settled through
/// [`LdapAuth::release_service_connection`] — the flow was cancelled by the
/// request deadline or a gRPC deadline while an operation was outstanding —
/// retires a shared connection synchronously. Its outstanding operation then
/// ends when the last concurrent borrower lets go and the connection closes,
/// instead of piling more work onto a connection the concurrency bound no
/// longer accounts for.
struct ServiceConnection<'a> {
    ldap: Ldap,
    /// The shared connection this handle belongs to, if any. A shared
    /// connection is never unbound by the flow that borrowed it.
    pooled: Option<Arc<PooledServiceConnection>>,
    endpoint: &'a LdapEndpoint,
    settled: bool,
}

impl Drop for ServiceConnection<'_> {
    fn drop(&mut self) {
        if !self.settled
            && let Some(pooled) = self.pooled.as_ref()
        {
            self.endpoint.retire_service_connection(pooled);
        }
    }
}

/// Recent consecutive credential failures for one presented username.
struct AccountFailures {
    consecutive: u32,
    last_failure: Instant,
    blocked_until: Option<Instant>,
}

impl AccountFailures {
    /// Whether this state still constrains its username: an active block, or
    /// a failure run whose quiet period has not elapsed.
    fn is_live(&self, now: Instant, backoff: Duration) -> bool {
        self.blocked_until.is_some_and(|until| now < until)
            || (self.consecutive > 0 && now.saturating_duration_since(self.last_failure) < backoff)
    }

    /// Count one more credential failure observed at `now`.
    fn record_failure(&mut self, now: Instant, threshold: u32, backoff: Duration) {
        // A lapsed block, or a quiet period as long as the backoff, starts a
        // new run of failures.
        let quiet_period_elapsed = now.saturating_duration_since(self.last_failure) >= backoff;
        let block_elapsed = self.blocked_until.is_some_and(|until| now >= until);
        if quiet_period_elapsed || block_elapsed {
            self.consecutive = 0;
            self.blocked_until = None;
        }
        self.consecutive = self.consecutive.saturating_add(1);
        self.last_failure = now;
        if self.consecutive >= threshold {
            self.blocked_until = now.checked_add(backoff);
            self.consecutive = 0;
        }
    }
}

/// Entries examined when the per-username tracker is full and a new username
/// needs a slot. Only state that no longer constrains anyone is reclaimed.
const LDAP_AUTH_ACCOUNT_PRUNE_SCAN: usize = 16;

/// Whether a presented username may reach the directory under the
/// per-username failure bound.
enum AccountAdmission {
    Allowed,
    /// Inside its failed-attempt backoff.
    Blocked,
    /// The tracker is full of live state, so a username it cannot track is
    /// refused rather than given unbounded attempts.
    Saturated,
}

/// Effective semantics a retained [`CredentialGuardState`] was built for. A
/// rebuild with equal semantics inherits the live state; any change gets
/// fresh state. Holds no credential, URL, or username.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CredentialGuardSemantics {
    realm: [u8; 32],
    negative_cache_ttl_secs: u64,
    max_failed_attempts_per_user: u32,
    failed_attempt_backoff_secs: u64,
    capacity: usize,
}

/// Rejected-credential cache and per-username failure tracker.
///
/// Owned by the stable policy identity (namespace + plugin-config id), not by
/// the instance a reload happens to construct: a compatible rebuild inherits
/// active backoffs and remembered rejections, and failures still finishing on
/// the retired generation land in the same state.
struct CredentialGuardState {
    semantics: CredentialGuardSemantics,
    /// Keys every digest in this state. Zeroized on drop.
    hmac_key: Zeroizing<[u8; 32]>,
    negative_cache: BoundedKeyMap<Instant>,
    account_failures: BoundedKeyMap<AccountFailures>,
}

type CredentialGuardRegistry = Mutex<HashMap<String, Vec<Weak<CredentialGuardState>>>>;

/// Weak registry of [`CredentialGuardState`] by policy identity. Entries are
/// pruned on insert, so retention is bounded by the configured policies plus
/// in-flight holders.
static CREDENTIAL_GUARD_STATES: OnceLock<CredentialGuardRegistry> = OnceLock::new();

impl CredentialGuardState {
    fn new(semantics: CredentialGuardSemantics, shard_amount: usize) -> Result<Arc<Self>, String> {
        let mut hmac_key = Zeroizing::new([0u8; 32]);
        crate::fips::backend::rand::SystemRandom::new()
            .fill(hmac_key.as_mut())
            .map_err(|_| "ldap_auth: failed to generate credential guard key".to_string())?;
        Ok(Arc::new(Self {
            semantics,
            hmac_key,
            negative_cache: BoundedKeyMap::new(shard_amount, semantics.capacity),
            account_failures: BoundedKeyMap::new(shard_amount, semantics.capacity),
        }))
    }

    /// The live state for `identity` with these semantics, or fresh state.
    /// Without an identity (validation and direct construction) the state is
    /// private to the instance.
    fn retain(
        identity: Option<&str>,
        semantics: CredentialGuardSemantics,
        shard_amount: usize,
    ) -> Result<Arc<Self>, String> {
        let Some(identity) = identity else {
            return Self::new(semantics, shard_amount);
        };
        let registry = CREDENTIAL_GUARD_STATES.get_or_init(|| Mutex::new(HashMap::new()));
        let mut guard = registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.retain(|_, states| {
            states.retain(|weak| weak.strong_count() > 0);
            !states.is_empty()
        });
        if let Some(existing) = guard.get(identity).and_then(|states| {
            states
                .iter()
                .filter_map(Weak::upgrade)
                .find(|state| state.semantics == semantics)
        }) {
            return Ok(existing);
        }
        let state = Self::new(semantics, shard_amount)?;
        guard
            .entry(identity.to_string())
            .or_default()
            .push(Arc::downgrade(&state));
        Ok(state)
    }

    /// Admission for a presented username whose digest is `key`.
    fn account_admission(&self, key: &CacheKey, now: Instant) -> AccountAdmission {
        let backoff = Duration::from_secs(self.semantics.failed_attempt_backoff_secs);
        if let Some(state) = self.account_failures.map.get(key) {
            return if state.blocked_until.is_some_and(|until| now < until) {
                AccountAdmission::Blocked
            } else {
                AccountAdmission::Allowed
            };
        }
        if self.account_failures.entries.load(Ordering::Acquire) < self.account_failures.capacity
            || self.prune_one_account(now, backoff)
        {
            AccountAdmission::Allowed
        } else {
            AccountAdmission::Saturated
        }
    }

    /// Reclaim one tracked username that no longer constrains anyone.
    /// Live counters and active blocks are never evicted.
    fn prune_one_account(&self, now: Instant, backoff: Duration) -> bool {
        let candidates: Vec<CacheKey> = self
            .account_failures
            .map
            .iter()
            .take(LDAP_AUTH_ACCOUNT_PRUNE_SCAN)
            .filter(|entry| !entry.value().is_live(now, backoff))
            .map(|entry| *entry.key())
            .collect();
        for key in candidates {
            if self
                .account_failures
                .map
                .remove_if(&key, |_, state| !state.is_live(now, backoff))
                .is_some()
            {
                self.account_failures.release();
                return true;
            }
        }
        false
    }

    /// Count one credential failure for `key` as a single per-key operation:
    /// concurrent first failures combine instead of overwriting each other.
    ///
    /// The slot is reserved while the key's shard is held through
    /// `DashMap::entry`, so a concurrent first failure for the same username
    /// either finds the winner's state (and adds to it) or reserves the slot
    /// itself; losing the last free slot to that winner cannot drop a count.
    fn record_account_failure(&self, key: CacheKey, now: Instant) {
        let threshold = self.semantics.max_failed_attempts_per_user;
        let backoff = Duration::from_secs(self.semantics.failed_attempt_backoff_secs);
        let mut pruned = false;
        loop {
            match self.account_failures.map.entry(key) {
                dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                    occupied.get_mut().record_failure(now, threshold, backoff);
                    return;
                }
                dashmap::mapref::entry::Entry::Vacant(vacant) => {
                    if self.account_failures.try_reserve() {
                        let mut state = AccountFailures {
                            consecutive: 0,
                            last_failure: now,
                            blocked_until: None,
                        };
                        state.record_failure(now, threshold, backoff);
                        vacant.insert(state);
                        return;
                    }
                }
            }
            // Full: reclaim one slot that no longer constrains anyone (with
            // the shard released), then try once more. A tracker full of
            // live state never evicts it; that username's next request is
            // refused at admission instead.
            if pruned || !self.prune_one_account(now, backoff) {
                return;
            }
            pruned = true;
        }
    }
}

/// A `DashMap` keyed by credential digests with an atomically enforced entry
/// cap. At capacity one existing entry is replaced instead of scanning the
/// map, matching the success cache.
struct BoundedKeyMap<V> {
    map: DashMap<CacheKey, V>,
    entries: AtomicUsize,
    capacity: usize,
}

impl<V> BoundedKeyMap<V> {
    fn new(shard_amount: usize, capacity: usize) -> Self {
        Self {
            map: DashMap::with_shard_amount(shard_amount),
            entries: AtomicUsize::new(0),
            capacity,
        }
    }

    fn get_copied(&self, key: &CacheKey) -> Option<V>
    where
        V: Copy,
    {
        self.map.get(key).map(|entry| *entry.value())
    }

    fn insert(&self, key: CacheKey, value: V) {
        if let Some(mut existing) = self.map.get_mut(&key) {
            *existing = value;
            return;
        }
        if !self.try_reserve() && (!self.evict_one() || !self.try_reserve()) {
            return;
        }
        match self.map.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                occupied.insert(value);
                self.release();
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(value);
            }
        }
    }

    fn remove(&self, key: &CacheKey) {
        if self.map.remove(key).is_some() {
            self.release();
        }
    }

    fn try_reserve(&self) -> bool {
        let mut current = self.entries.load(Ordering::Acquire);
        loop {
            if current >= self.capacity {
                return false;
            }
            match self.entries.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn release(&self) {
        if self
            .entries
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(1)
            })
            .is_err()
        {
            warn!("ldap_auth: bounded map accounting underflow prevented");
        }
    }

    fn evict_one(&self) -> bool {
        let victim = self.map.iter().next().map(|entry| *entry.key());
        let Some(victim) = victim else {
            return false;
        };
        if self.map.remove(&victim).is_some() {
            self.release();
            true
        } else {
            false
        }
    }
}

/// Outcome of an LDAP authentication attempt, distinguishing a genuine
/// credential-negative result (wrong password / user not found) from a
/// backend or configuration failure (directory unreachable, service-account
/// bind rejected, search RPC error).
///
/// `verify()` maps `Credential` to `VerifyOutcome::Invalid` (HTTP 401) and
/// `Backend` to `VerifyOutcome::Internal` (HTTP 500), mirroring the existing
/// group-membership path so the two paths are consistent. Returning 401 for a
/// directory outage or misconfigured service account would tell the client its
/// credentials are wrong — prompting credential re-submission and masking the
/// operational problem (finding #32). Each variant carries the specific cause
/// for the `warn!` log only; the client always sees a generic message.
enum AuthError {
    /// The presented credentials were rejected, or the user does not exist.
    /// Maps to 401.
    Credential(String),
    /// The directory was unreachable, the service account failed/was rejected,
    /// or a search RPC failed. Operational/config problem, not the client's
    /// fault. Maps to 500.
    Backend(String),
    /// The endpoint in use could not be reached, its connection failed, or it
    /// answered `busy` (51) / `unavailable` (52). Another configured endpoint
    /// may still answer, so the flow fails over; maps to 500 once every
    /// endpoint failed.
    Unavailable(String),
}

impl AuthError {
    /// The specific cause, for operator-facing `warn!` logs only — never sent
    /// to the client.
    fn log_message(&self) -> &str {
        match self {
            AuthError::Credential(msg) | AuthError::Backend(msg) | AuthError::Unavailable(msg) => {
                msg
            }
        }
    }
}

/// LDAP result codes that say "this server cannot serve the request now"
/// rather than anything about the request: `busy` (51) and `unavailable` (52).
fn is_unavailable_result_code(rc: u32) -> bool {
    matches!(rc, 51 | 52)
}

/// Classify a non-success directory result of an operation whose failure is
/// never the end user's fault (service bind, searches).
fn directory_result_error(result: &ldap3::LdapResult, context: &str) -> AuthError {
    let message = format!("ldap_auth: {context} failed with directory result: {result}");
    if is_unavailable_result_code(result.rc) {
        AuthError::Unavailable(message)
    } else {
        AuthError::Backend(message)
    }
}

/// A transport-level failure (I/O error, operation timeout, closed
/// connection) of an LDAP operation: the endpoint, not the request, failed.
fn transport_error(context: &str, error: ldap3::LdapError) -> AuthError {
    AuthError::Unavailable(format!("ldap_auth: {context} failed: {error}"))
}

fn classify_user_bind_result(result: ldap3::LdapResult, context: &str) -> Result<(), AuthError> {
    match result.rc {
        0 => Ok(()),
        49 => Err(AuthError::Credential(format!(
            "ldap_auth: {context} rejected: {result}"
        ))),
        rc if is_unavailable_result_code(rc) => Err(AuthError::Unavailable(format!(
            "ldap_auth: {context} failed with directory result: {result}"
        ))),
        _ => Err(AuthError::Backend(format!(
            "ldap_auth: {context} failed with directory result: {result}"
        ))),
    }
}

pub struct LdapAuth {
    /// `ldap_url` first, then every `failover_ldap_urls` entry in order.
    endpoints: Vec<LdapEndpoint>,
    /// Direct bind: "uid={username},ou=users,dc=example,dc=com"
    bind_dn_template: Option<String>,
    /// Search-then-bind base DN
    search_base_dn: Option<String>,
    /// Search filter with {username} placeholder, e.g. "(&(objectClass=person)(sAMAccountName={username}))"
    search_filter: Option<String>,
    /// Attribute returned by search-then-bind and used as the Ferrum identity
    /// and username-based group-authorization value.
    canonical_identity_attribute: Option<String>,
    /// Service account for search-then-bind
    service_account_dn: Option<String>,
    service_account_password: Option<String>,
    /// Group membership filtering
    group_base_dn: Option<String>,
    group_filter: Option<String>,
    required_groups: Vec<String>,
    /// `required_groups` prepared with [`prepare_case_ignore`].
    required_group_lookup: HashSet<String>,
    /// Authoritative group-name attribute. When a returned group entry carries
    /// it, only its values decide the match.
    group_attribute: String,
    /// DN-valued membership attribute (`group_member_attribute`); `None`
    /// keeps the built-in `member` / `uniqueMember` / `memberUid` predicate.
    group_member_attribute: Option<String>,
    group_membership_mode: GroupMembershipMode,
    /// `member_of` mode: subtree filter selecting the required groups by their
    /// authoritative `group_attribute` value, built once at construction.
    member_of_group_filter: Option<String>,
    /// Use STARTTLS on ldap:// connections
    starttls: bool,
    /// LDAP connection timeout
    connect_timeout: Duration,
    /// Server-side time limit applied to each LDAP search.
    search_time_limit_seconds: i32,
    /// Strict wall-clock deadline for one complete uncached authentication.
    request_timeout: Duration,
    /// Immediate admission bound for uncached LDAP authentication work.
    ldap_concurrency: Arc<Semaphore>,
    /// Cache TTL for successful auth results (0 = disabled)
    cache_ttl: Duration,
    /// Longest a cache hit is admitted without re-checking `required_groups`
    /// (0 = re-check on every hit).
    group_cache_ttl: Duration,
    /// In-memory cache keyed by a process-random HMAC over username + password.
    cache: Arc<DashMap<CacheKey, CacheEntry>>,
    cache_entries: AtomicUsize,
    /// Source of [`CacheEntry::generation`].
    cache_generation: AtomicU64,
    /// Zeroized on drop. A full-memory compromise can still recover this key.
    cache_hmac_key: Option<Zeroizing<[u8; 32]>>,
    /// Maximum entries in the auth result cache. Prevents unbounded growth
    /// from brute-force attempts with unique credentials. Default: 10000.
    max_cache_entries: usize,
    /// How long an exact rejected credential is refused without contacting
    /// the directory (0 = disabled).
    negative_cache_ttl: Duration,
    /// Consecutive credential failures after which a presented username is
    /// refused without contacting the directory (0 = disabled).
    max_failed_attempts_per_user: u32,
    /// Rejected-credential cache and per-username failure tracker, retained
    /// across compatible rebuilds of the same policy. `None` when both
    /// bounds are disabled.
    credential_guard: Option<Arc<CredentialGuardState>>,
    /// Longest a bound service-account connection is reused for searches
    /// (0 = a fresh connection per flow).
    service_connection_max_age: Duration,
    /// Remove the verified `Authorization: Basic` credential from the backend
    /// request. Default `true`, matching `key_auth`.
    hide_credentials: bool,
    /// Request headers whose values carry reusable credentials and must be
    /// omitted from diagnostics and policy calls.
    request_headers_to_redact: Vec<String>,
    /// Pre-built rustls `ClientConfig` for LDAP TLS connections.
    /// Integrates `FERRUM_TLS_CA_BUNDLE_PATH` (exclusive trust) and
    /// `FERRUM_TLS_NO_VERIFY`. `Arc` so reuse across reconnects is cheap and
    /// matches `LdapConnSettings::set_config()`'s expected type.
    tls_config: Option<Arc<ClientConfig>>,
    /// Whether to skip TLS verification (passed to ldap3 for IP-address handling).
    tls_no_verify: bool,
    /// Resolver with a cache-bypassing dial path. In production this is the
    /// gateway's shared resolver; cache-less test/validation clients receive a
    /// private resolver carrying the same backend policy.
    dns_cache: DnsCache,
    /// Active backend policy rechecked immediately before each socket opens.
    backend_egress_policy: crate::config::BackendEgressPolicy,
    /// Plaintext loopback endpoints are admitted without the development-only
    /// override, but their actual dial-time answers must remain loopback.
    plaintext_requires_loopback: bool,
    /// Verifying-authority digest (directory URL, bind/search base, and
    /// identity attribute) committed with every external principal this
    /// instance vouches for.
    identity_realm_authority: [u8; 32],
}

impl LdapAuth {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::new_with_config_id(config, http_client, None)
    }

    /// Construct with the stable plugin-config id. The id, with the client's
    /// namespace, owns the rejected-credential and per-username failure state
    /// so a compatible reload inherits it; `None` keeps the state private.
    pub fn new_with_config_id(
        config: &Value,
        http_client: PluginHttpClient,
        plugin_config_id: Option<&str>,
    ) -> Result<Self, String> {
        if plugin_config_id.is_some_and(|config_id| config_id.trim().is_empty()) {
            return Err("ldap_auth: plugin config id must not be blank".to_string());
        }
        let config_obj = config
            .as_object()
            .ok_or_else(|| "ldap_auth: config must be an object".to_string())?;
        reject_unknown_config_keys(config_obj)?;

        let primary_url = parse_ldap_url_value(parse_required_ldap_url(config_obj)?, "ldap_url")?;
        let is_ldaps = primary_url.is_ldaps;
        let failover_urls = parse_failover_ldap_urls(config_obj)?;
        // One scheme for every endpoint: `starttls`, the TLS client config, and
        // the plaintext rules below are decided once for the whole set.
        if let Some(index) = failover_urls
            .iter()
            .position(|endpoint| endpoint.is_ldaps != is_ldaps)
        {
            return Err(format!(
                "ldap_auth: `failover_ldap_urls[{index}]` must use the same scheme as `ldap_url`"
            ));
        }

        let bind_dn_template = parse_optional_string(config_obj, "bind_dn_template")?;

        let search_base_dn = parse_optional_string(config_obj, "search_base_dn")?;

        let search_filter = parse_optional_string(config_obj, "search_filter")?;

        let canonical_identity_attribute =
            parse_optional_string(config_obj, "canonical_identity_attribute")?;

        let service_account_dn = parse_optional_string(config_obj, "service_account_dn")?;

        let service_account_password =
            parse_optional_secret_string(config_obj, "service_account_password")?;

        // Validate: must have either bind_dn_template or search-then-bind config
        let has_direct_bind = bind_dn_template.is_some();
        let has_search_bind = search_base_dn.is_some() && search_filter.is_some();

        if !has_direct_bind && !has_search_bind {
            return Err(
                "ldap_auth: must configure either `bind_dn_template` for direct bind, \
                 or both `search_base_dn` and `search_filter` for search-then-bind"
                    .to_string(),
            );
        }

        // Direct bind and search-then-bind are alternatives, not layers. Taking
        // the direct-bind branch while a search block is configured would leave
        // the search keys silently inert, so refuse the ambiguous shape outright.
        if has_direct_bind && (search_base_dn.is_some() || search_filter.is_some()) {
            return Err(
                "ldap_auth: `bind_dn_template` (direct bind) cannot be combined with the \
                 search-then-bind keys `search_base_dn`/`search_filter`; configure exactly \
                 one authentication mode"
                    .to_string(),
            );
        }

        if has_search_bind && (service_account_dn.is_none() || service_account_password.is_none()) {
            return Err(
                "ldap_auth: search-then-bind mode requires `service_account_dn` and \
                 `service_account_password`"
                    .to_string(),
            );
        }

        if canonical_identity_attribute.is_none() {
            return Err(
                "ldap_auth: both bind modes require `canonical_identity_attribute` so the authenticated directory entry, not the presented username, defines the Ferrum identity"
                    .to_string(),
            );
        }

        if let Some(ref tmpl) = bind_dn_template
            && !tmpl.contains("{username}")
        {
            return Err(
                "ldap_auth: `bind_dn_template` must contain `{username}` placeholder".to_string(),
            );
        }

        if let Some(ref f) = search_filter {
            if !f.contains("{username}") {
                return Err(
                    "ldap_auth: `search_filter` must contain `{username}` placeholder".to_string(),
                );
            }
            validate_ldap_filter_syntax(f, "search_filter")?;
        }

        // Distinguished names and attribute descriptions are checked at
        // admission, like filters: a malformed value would otherwise pass
        // `validate`, the admin API, and startup, and then fail every request.
        if let Some(ref tmpl) = bind_dn_template {
            validate_bind_name(
                &tmpl.replace(
                    "{username}",
                    &escape_dn_value(LDAP_FILTER_VALIDATION_USERNAME),
                ),
                "bind_dn_template",
            )?;
        }
        if let Some(ref dn) = service_account_dn {
            validate_bind_name(dn, "service_account_dn")?;
        }
        if let Some(ref dn) = search_base_dn {
            validate_distinguished_name(dn, "search_base_dn")?;
        }
        if let Some(ref attribute) = canonical_identity_attribute {
            validate_attribute_description(attribute, "canonical_identity_attribute")?;
        }

        // Group filtering config
        let group_base_dn = parse_optional_string(config_obj, "group_base_dn")?;
        if let Some(ref dn) = group_base_dn {
            validate_distinguished_name(dn, "group_base_dn")?;
        }

        let group_filter = parse_optional_string(config_obj, "group_filter")?;
        if let Some(ref f) = group_filter {
            validate_ldap_filter_syntax(f, "group_filter")?;
        }

        let required_groups = parse_string_array(config_obj, "required_groups")?;
        let required_group_lookup = required_groups
            .iter()
            .map(|group| prepare_case_ignore(group.as_str()))
            .collect();

        if !required_groups.is_empty() && group_base_dn.is_none() {
            return Err(
                "ldap_auth: `group_base_dn` is required when `required_groups` is set".to_string(),
            );
        }

        if !required_groups.is_empty()
            && group_filter.as_ref().is_some_and(|filter| {
                !filter.contains("{user_dn}") && !filter.contains("{username}")
            })
        {
            return Err(
                "ldap_auth: `group_filter` must contain `{user_dn}` or `{username}` when `required_groups` is set"
                    .to_string(),
            );
        }

        // Finding #33: when group enforcement is configured but no service
        // account is available, the group-membership search runs over an
        // ANONYMOUS-bound connection. Many directories deny anonymous reads of
        // group objects / `member` attributes, so the search silently returns
        // zero entries and a legitimately entitled user gets a 403. Surface
        // this dependency on directory ACLs at config time rather than as
        // silent denials at request time. (Search-then-bind already mandates a
        // service account above, so this only fires for direct-bind configs.)
        if !required_groups.is_empty()
            && (service_account_dn.is_none() || service_account_password.is_none())
        {
            warn!(
                "ldap_auth: 'required_groups' is set without a service account \
                 ('service_account_dn'/'service_account_password'); the group-membership search \
                 will use an ANONYMOUS bind. Group enforcement will only work if the directory \
                 permits anonymous reads of group objects — otherwise entitled users will be \
                 denied (403). Configure a service account to avoid relying on directory ACLs."
            );
        }

        let group_attribute =
            parse_optional_string(config_obj, "group_attribute")?.unwrap_or_else(|| "cn".into());
        validate_attribute_description(&group_attribute, "group_attribute")?;

        let group_member_attribute = parse_optional_string(config_obj, "group_member_attribute")?;
        if let Some(ref attribute) = group_member_attribute {
            validate_attribute_description(attribute, "group_member_attribute")?;
        }
        let group_membership_mode = match config_obj.get("group_membership_mode").map(Value::as_str)
        {
            None | Some(Some("direct")) => GroupMembershipMode::Direct,
            Some(Some("ad_in_chain")) => GroupMembershipMode::AdInChain,
            Some(Some("member_of")) => GroupMembershipMode::MemberOf,
            Some(_) => {
                return Err(
                    "ldap_auth: `group_membership_mode` must be `direct`, `ad_in_chain`, or `member_of`"
                        .to_string(),
                );
            }
        };
        // `member_of` selects the required groups by name itself; a custom
        // group filter would be a second, conflicting membership definition.
        if group_membership_mode == GroupMembershipMode::MemberOf && group_filter.is_some() {
            return Err(
                "ldap_auth: `group_filter` cannot be combined with `group_membership_mode: member_of`"
                    .to_string(),
            );
        }
        let member_of_group_filter = (group_membership_mode == GroupMembershipMode::MemberOf
            && !required_groups.is_empty())
        .then(|| required_group_name_filter(&group_attribute, &required_groups));
        if let Some(ref filter) = member_of_group_filter {
            validate_ldap_filter_syntax(filter, "required_groups")?;
        }
        // The membership predicate is built from validated attribute names, so
        // this only guards the composed shape (including the AD extensible
        // match) against the same grammar `ldap3` applies on the wire.
        if group_membership_mode != GroupMembershipMode::MemberOf
            && parse_filter(group_membership_filter(
                group_membership_mode,
                group_member_attribute.as_deref(),
                LDAP_FILTER_VALIDATION_USER_DN,
                LDAP_FILTER_VALIDATION_USERNAME,
            ))
            .is_err()
        {
            return Err(
                "ldap_auth: `group_member_attribute` / `group_membership_mode` do not form a valid LDAP membership filter"
                    .to_string(),
            );
        }

        let starttls = parse_bool(config_obj, "starttls", false)?;

        if starttls && is_ldaps {
            return Err(
                "ldap_auth: `starttls` cannot be used with `ldaps://` URLs (STARTTLS is for upgrading ldap:// connections)"
                    .to_string(),
            );
        }

        let connect_timeout_secs = parse_u64(
            config_obj,
            "connect_timeout_seconds",
            LDAP_AUTH_DEFAULT_CONNECT_TIMEOUT_SECONDS,
        )?;
        if connect_timeout_secs == 0 {
            return Err(
                "ldap_auth: `connect_timeout_seconds` must be greater than zero".to_string(),
            );
        }
        if connect_timeout_secs > LDAP_AUTH_MAX_CONNECT_TIMEOUT_SECONDS {
            return Err(format!(
                "ldap_auth: `connect_timeout_seconds` must not exceed {LDAP_AUTH_MAX_CONNECT_TIMEOUT_SECONDS}"
            ));
        }
        let search_time_limit_seconds = i32::try_from(connect_timeout_secs).map_err(|_| {
            "ldap_auth: `connect_timeout_seconds` cannot be represented as an LDAP search time limit"
                .to_string()
        })?;

        let default_request_timeout_secs =
            LDAP_AUTH_DEFAULT_REQUEST_TIMEOUT_SECONDS.max(connect_timeout_secs);
        let request_timeout_secs = parse_u64(
            config_obj,
            "request_timeout_seconds",
            default_request_timeout_secs,
        )?;
        if request_timeout_secs == 0 {
            return Err(
                "ldap_auth: `request_timeout_seconds` must be greater than zero".to_string(),
            );
        }
        if request_timeout_secs > LDAP_AUTH_MAX_REQUEST_TIMEOUT_SECONDS {
            return Err(format!(
                "ldap_auth: `request_timeout_seconds` must not exceed {LDAP_AUTH_MAX_REQUEST_TIMEOUT_SECONDS}"
            ));
        }

        let max_concurrent_requests = parse_usize(
            config_obj,
            "max_concurrent_requests",
            LDAP_AUTH_DEFAULT_MAX_CONCURRENT_REQUESTS,
        )?;
        if max_concurrent_requests == 0 {
            return Err(
                "ldap_auth: `max_concurrent_requests` must be greater than zero".to_string(),
            );
        }
        if max_concurrent_requests > LDAP_AUTH_MAX_CONCURRENT_REQUESTS {
            return Err(format!(
                "ldap_auth: `max_concurrent_requests` must not exceed {LDAP_AUTH_MAX_CONCURRENT_REQUESTS}"
            ));
        }

        let cache_ttl_secs = parse_u64(
            config_obj,
            "cache_ttl_seconds",
            LDAP_AUTH_DEFAULT_CACHE_TTL_SECONDS,
        )?;
        if cache_ttl_secs > LDAP_AUTH_MAX_CACHE_TTL_SECONDS {
            return Err(format!(
                "ldap_auth: `cache_ttl_seconds` must not exceed {LDAP_AUTH_MAX_CACHE_TTL_SECONDS}"
            ));
        }

        let group_cache_ttl_secs = parse_u64(
            config_obj,
            "group_cache_ttl_seconds",
            LDAP_AUTH_DEFAULT_GROUP_CACHE_TTL_SECONDS,
        )?;
        if group_cache_ttl_secs > LDAP_AUTH_MAX_CACHE_TTL_SECONDS {
            return Err(format!(
                "ldap_auth: `group_cache_ttl_seconds` must not exceed {LDAP_AUTH_MAX_CACHE_TTL_SECONDS}"
            ));
        }
        if cache_ttl_secs > LDAP_AUTH_CACHE_TTL_WARN_SECONDS {
            warn!(
                cache_ttl_seconds = cache_ttl_secs,
                "ldap_auth: a cached credential keeps authenticating for up to \
                 'cache_ttl_seconds' after its password changes or its account is disabled in \
                 the directory; group membership is re-checked every \
                 'group_cache_ttl_seconds'. Lower 'cache_ttl_seconds' to shorten that lag."
            );
        }

        let max_cache_entries = parse_usize(
            config_obj,
            "max_cache_entries",
            LDAP_AUTH_DEFAULT_MAX_CACHE_ENTRIES,
        )?;
        if max_cache_entries == 0 {
            return Err("ldap_auth: `max_cache_entries` must be greater than zero".to_string());
        }
        if max_cache_entries > LDAP_AUTH_MAX_CACHE_ENTRIES_LIMIT {
            return Err(format!(
                "ldap_auth: `max_cache_entries` must not exceed {LDAP_AUTH_MAX_CACHE_ENTRIES_LIMIT}"
            ));
        }

        // Basic credentials are a reusable directory password, typically the
        // user's corporate password. Removing them from the backend request by
        // default keeps them inside the gateway trust boundary; `key_auth`
        // established the same default for its reusable API keys.
        let hide_credentials = parse_bool(config_obj, "hide_credentials", true)?;

        let negative_cache_ttl_secs = parse_u64(config_obj, "negative_cache_ttl_seconds", 0)?;
        if negative_cache_ttl_secs > LDAP_AUTH_MAX_NEGATIVE_CACHE_TTL_SECONDS {
            return Err(format!(
                "ldap_auth: `negative_cache_ttl_seconds` must not exceed {LDAP_AUTH_MAX_NEGATIVE_CACHE_TTL_SECONDS}"
            ));
        }
        let max_failed_attempts_per_user =
            parse_u64(config_obj, "max_failed_attempts_per_user", 0)?;
        if max_failed_attempts_per_user > LDAP_AUTH_MAX_FAILED_ATTEMPTS_PER_USER {
            return Err(format!(
                "ldap_auth: `max_failed_attempts_per_user` must not exceed {LDAP_AUTH_MAX_FAILED_ATTEMPTS_PER_USER}"
            ));
        }
        let max_failed_attempts_per_user = u32::try_from(max_failed_attempts_per_user)
            .map_err(|_| "ldap_auth: `max_failed_attempts_per_user` is too large".to_string())?;
        let failed_attempt_backoff_secs = parse_u64(
            config_obj,
            "failed_attempt_backoff_seconds",
            LDAP_AUTH_DEFAULT_FAILED_ATTEMPT_BACKOFF_SECONDS,
        )?;
        if failed_attempt_backoff_secs == 0 {
            return Err(
                "ldap_auth: `failed_attempt_backoff_seconds` must be greater than zero".to_string(),
            );
        }
        if failed_attempt_backoff_secs > LDAP_AUTH_MAX_FAILED_ATTEMPT_BACKOFF_SECONDS {
            return Err(format!(
                "ldap_auth: `failed_attempt_backoff_seconds` must not exceed {LDAP_AUTH_MAX_FAILED_ATTEMPT_BACKOFF_SECONDS}"
            ));
        }

        let service_connection_max_age_secs =
            parse_u64(config_obj, "service_connection_max_age_seconds", 0)?;
        if service_connection_max_age_secs > LDAP_AUTH_MAX_SERVICE_CONNECTION_MAX_AGE_SECONDS {
            return Err(format!(
                "ldap_auth: `service_connection_max_age_seconds` must not exceed {LDAP_AUTH_MAX_SERVICE_CONNECTION_MAX_AGE_SECONDS}"
            ));
        }
        if service_connection_max_age_secs > 0
            && (service_account_dn.is_none() || service_account_password.is_none())
        {
            return Err(
                "ldap_auth: `service_connection_max_age_seconds` reuses the service-account connection and requires `service_account_dn` and `service_account_password`"
                    .to_string(),
            );
        }

        let allow_plaintext = parse_bool(config_obj, "allow_plaintext", false)?;
        let plaintext_requires_loopback = !is_ldaps && !starttls && !allow_plaintext;
        if !is_ldaps && !starttls {
            for endpoint in std::iter::once(&primary_url).chain(failover_urls.iter()) {
                if is_loopback_ldap_endpoint(&endpoint.parsed) {
                    continue;
                }
                if !allow_plaintext {
                    return Err(format!(
                        "ldap_auth: non-loopback `ldap://` endpoints require STARTTLS or LDAPS (`{}`); set `allow_plaintext: true` only for an isolated development environment",
                        endpoint.field
                    ));
                }
                warn!(
                    "ldap_auth: ALLOWING PLAINTEXT LDAP to a non-loopback endpoint; service-account and user passwords have no transport confidentiality ('allow_plaintext: true' is development-only)"
                );
            }
        }

        let cache_hmac_key = if cache_ttl_secs == 0 {
            None
        } else {
            let mut key = Zeroizing::new([0u8; 32]);
            crate::fips::backend::rand::SystemRandom::new()
                .fill(key.as_mut())
                .map_err(|_| "ldap_auth: failed to generate cache HMAC key".to_string())?;
            Some(key)
        };
        let cache_shard_amount = http_client.pool_shard_amount();
        let backend_egress_policy = http_client.backend_allow_ips().clone();
        let dns_cache = http_client.dns_cache().cloned().unwrap_or_else(|| {
            DnsCache::new(DnsConfig {
                backend_allow_ips: backend_egress_policy.clone(),
                ..DnsConfig::default()
            })
        });

        // Build rustls TLS config respecting gateway settings, including the
        // gateway's parsed CRL list (`FERRUM_TLS_CRL_FILE_PATH`) so revoked LDAP
        // server certificates are rejected — parity with the proxy backend /
        // DTLS / rustls logging-sink surfaces (finding #84).
        let tls_no_verify = http_client.tls_no_verify();
        let needs_tls = is_ldaps || starttls;
        let tls_config = if needs_tls {
            Some(build_ldap_tls_config(
                tls_no_verify,
                http_client.tls_ca_bundle_path(),
                http_client.tls_crls(),
                Some(&http_client),
            )?)
        } else {
            None
        };

        let mut identity_realm_authority = auth_flow::external_identity_realm_authority(
            "ldap_auth",
            &[
                ("ldap_url", Some(primary_url.url.as_str())),
                ("bind_dn_template", bind_dn_template.as_deref()),
                ("search_base_dn", search_base_dn.as_deref()),
                (
                    "canonical_identity_attribute",
                    canonical_identity_attribute.as_deref(),
                ),
            ],
        );
        // Failover replicas vouch for identities too, so they join the realm.
        // Order-independent; a single-endpoint realm is unchanged.
        if !failover_urls.is_empty() {
            let mut replicas: Vec<&str> = failover_urls
                .iter()
                .map(|endpoint| endpoint.url.as_str())
                .collect();
            replicas.sort_unstable();
            let replicas = replicas.join("\n");
            identity_realm_authority = auth_flow::refine_external_identity_realm_authority(
                &identity_realm_authority,
                "failover_ldap_urls",
                Some(replicas.as_str()),
            );
        }

        // The rejected-credential cache and the per-username tracker survive a
        // compatible reload of this policy; a changed directory, bound, or
        // capacity starts from fresh state.
        let credential_guard = if negative_cache_ttl_secs == 0 && max_failed_attempts_per_user == 0
        {
            None
        } else {
            let identity = plugin_config_id
                .map(|config_id| format!("{}\u{1f}{config_id}", http_client.namespace()));
            Some(CredentialGuardState::retain(
                identity.as_deref(),
                CredentialGuardSemantics {
                    realm: identity_realm_authority,
                    negative_cache_ttl_secs,
                    max_failed_attempts_per_user,
                    failed_attempt_backoff_secs,
                    capacity: max_cache_entries,
                },
                cache_shard_amount,
            )?)
        };

        let endpoints = std::iter::once(primary_url)
            .chain(failover_urls)
            .map(|endpoint| LdapEndpoint {
                url: endpoint.url,
                hostname: endpoint.hostname,
                port: endpoint.port,
                service_connection: ArcSwapOption::empty(),
            })
            .collect();

        Ok(Self {
            endpoints,
            bind_dn_template,
            search_base_dn,
            search_filter,
            canonical_identity_attribute,
            service_account_dn,
            service_account_password,
            group_base_dn,
            group_filter,
            required_groups,
            required_group_lookup,
            group_attribute,
            group_member_attribute,
            group_membership_mode,
            member_of_group_filter,
            starttls,
            connect_timeout: Duration::from_secs(connect_timeout_secs),
            search_time_limit_seconds,
            request_timeout: Duration::from_secs(request_timeout_secs),
            ldap_concurrency: Arc::new(Semaphore::new(max_concurrent_requests)),
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            group_cache_ttl: Duration::from_secs(group_cache_ttl_secs),
            cache: Arc::new(DashMap::with_shard_amount(cache_shard_amount)),
            cache_entries: AtomicUsize::new(0),
            cache_generation: AtomicU64::new(0),
            cache_hmac_key,
            max_cache_entries,
            negative_cache_ttl: Duration::from_secs(negative_cache_ttl_secs),
            max_failed_attempts_per_user,
            credential_guard,
            service_connection_max_age: Duration::from_secs(service_connection_max_age_secs),
            hide_credentials,
            request_headers_to_redact: vec!["authorization".to_string()],
            tls_config,
            tls_no_verify,
            dns_cache,
            backend_egress_policy,
            plaintext_requires_loopback,
            identity_realm_authority,
        })
    }

    /// Build an opaque cache key using the per-instance random HMAC key.
    fn cache_key(&self, username: &str, password: &str) -> Option<CacheKey> {
        let key = self.cache_hmac_key.as_deref()?;
        credential_digest(key, CREDENTIAL_KEY_DOMAIN_SUCCESS, username, Some(password))
    }

    /// `true` when this exact credential was rejected by the directory within
    /// `negative_cache_ttl_seconds`.
    fn credential_recently_rejected(&self, username: &str, password: &str) -> bool {
        if self.negative_cache_ttl.is_zero() {
            return false;
        }
        let Some(guard) = self.credential_guard.as_deref() else {
            return false;
        };
        let Some(key) = credential_digest(
            &guard.hmac_key,
            CREDENTIAL_KEY_DOMAIN_REJECTED,
            username,
            Some(password),
        ) else {
            return false;
        };
        let Some(expires_at) = guard.negative_cache.get_copied(&key) else {
            return false;
        };
        if Instant::now() < expires_at {
            return true;
        }
        guard.negative_cache.remove(&key);
        false
    }

    /// Digest of the presented username for the per-username failure bound.
    ///
    /// Unlike the credential caches this key folds the username the way most
    /// directories match logins ([`prepare_case_ignore`]). Folding here can
    /// only make the bound stricter (spellings of one login share a budget,
    /// so a spray cannot dodge it by varying case); it never lets one login's
    /// result stand in for another's.
    fn account_key(&self, guard: &CredentialGuardState, username: &str) -> Option<CacheKey> {
        credential_digest(
            &guard.hmac_key,
            CREDENTIAL_KEY_DOMAIN_ACCOUNT,
            &prepare_case_ignore(username),
            None,
        )
    }

    /// Admission under the per-username failure bound.
    fn account_admission(&self, username: &str) -> AccountAdmission {
        if self.max_failed_attempts_per_user == 0 {
            return AccountAdmission::Allowed;
        }
        let Some(guard) = self.credential_guard.as_deref() else {
            return AccountAdmission::Allowed;
        };
        let Some(key) = self.account_key(guard, username) else {
            return AccountAdmission::Allowed;
        };
        guard.account_admission(&key, Instant::now())
    }

    /// Record a directory credential rejection (wrong password or unknown
    /// user) for the negative cache and the per-username failure count.
    fn record_credential_failure(&self, username: &str, password: &str) {
        let Some(guard) = self.credential_guard.as_deref() else {
            return;
        };
        let now = Instant::now();
        if !self.negative_cache_ttl.is_zero()
            && let Some(key) = credential_digest(
                &guard.hmac_key,
                CREDENTIAL_KEY_DOMAIN_REJECTED,
                username,
                Some(password),
            )
            && let Some(expires_at) = now.checked_add(self.negative_cache_ttl)
        {
            guard.negative_cache.insert(key, expires_at);
        }
        if self.max_failed_attempts_per_user > 0
            && let Some(key) = self.account_key(guard, username)
        {
            guard.record_account_failure(key, now);
        }
    }

    /// A successful authentication ends the username's failure run.
    fn clear_account_failures(&self, username: &str) {
        if self.max_failed_attempts_per_user == 0 {
            return;
        }
        if let Some(guard) = self.credential_guard.as_deref()
            && let Some(key) = self.account_key(guard, username)
        {
            guard.account_failures.remove(&key);
        }
    }

    /// Check if a successful auth result is cached and still valid.
    fn check_cache(&self, username: &str, password: &str) -> Option<CachedAuthentication> {
        if self.cache_ttl.is_zero() {
            return None;
        }
        let key = self.cache_key(username, password)?;
        if let Some(entry) = self.cache.get(&key) {
            let now = Instant::now();
            if now < entry.expires_at {
                return Some(CachedAuthentication {
                    canonical_identity: entry.canonical_identity.clone(),
                    user_dn: entry.user_dn.clone(),
                    groups_due: !self.required_groups.is_empty()
                        && now >= entry.groups_verified_until,
                    expires_at: entry.expires_at,
                    generation: entry.generation,
                });
            }
            // Expired — remove exactly the entry observed, never a replacement
            // admitted since.
            let generation = entry.generation;
            drop(entry);
            self.remove_cache_generation(&key, generation);
        }
        None
    }

    fn remove_cache_generation(&self, key: &CacheKey, generation: u64) -> bool {
        if self
            .cache
            .remove_if(key, |_, entry| entry.generation == generation)
            .is_some()
        {
            self.release_cache_slot();
            return true;
        }
        false
    }

    /// Cache a successful authentication result.
    fn set_cache(&self, username: &str, password: &str, user: &AuthenticatedUser) {
        if self.cache_ttl.is_zero() {
            return;
        }
        let Some(key) = self.cache_key(username, password) else {
            return;
        };
        let now = Instant::now();
        let Some(expires_at) = now.checked_add(self.cache_ttl) else {
            warn!("ldap_auth: cache expiry could not be represented; skipping cache admission");
            return;
        };
        // Never later than the entry's own expiry.
        let groups_verified_until = now
            .checked_add(self.group_cache_ttl)
            .map_or(expires_at, |until| until.min(expires_at));
        let generation = self.cache_generation.fetch_add(1, Ordering::Relaxed);
        let new_entry = || CacheEntry {
            expires_at,
            canonical_identity: user.canonical_identity.clone(),
            user_dn: user.dn.clone(),
            groups_verified_until,
            generation,
        };

        if let Some(mut existing) = self.cache.get_mut(&key) {
            *existing = new_entry();
            return;
        }

        if !self.try_reserve_cache_slot() {
            // Bounded replacement: evict at most one entry instead of scanning
            // the entire map on every saturated-cache miss.
            if !self.evict_one_cache_entry() || !self.try_reserve_cache_slot() {
                return;
            }
        }

        match self.cache.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                occupied.insert(new_entry());
                self.release_cache_slot();
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(new_entry());
            }
        }
    }

    /// Record a successful group re-check on the exact entry it was run for.
    /// Returns `false` when that entry expired or was replaced meanwhile, in
    /// which case the re-check must not admit the request.
    fn mark_cached_groups_verified(&self, username: &str, password: &str, generation: u64) -> bool {
        let Some(key) = self.cache_key(username, password) else {
            return false;
        };
        let Some(mut entry) = self.cache.get_mut(&key) else {
            return false;
        };
        let now = Instant::now();
        if entry.generation != generation || now >= entry.expires_at {
            return false;
        }
        entry.groups_verified_until = now
            .checked_add(self.group_cache_ttl)
            .map_or(entry.expires_at, |until| until.min(entry.expires_at));
        true
    }

    /// Drop the exact cached authentication a group re-check refused.
    fn evict_cached_authentication(&self, username: &str, password: &str, generation: u64) {
        if let Some(key) = self.cache_key(username, password) {
            self.remove_cache_generation(&key, generation);
        }
    }

    fn release_cache_slot(&self) {
        if self
            .cache_entries
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(1)
            })
            .is_err()
        {
            warn!("ldap_auth: cache entry accounting underflow prevented");
        }
    }

    fn try_reserve_cache_slot(&self) -> bool {
        let mut current = self.cache_entries.load(Ordering::Acquire);
        loop {
            if current >= self.max_cache_entries {
                return false;
            }
            match self.cache_entries.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn evict_one_cache_entry(&self) -> bool {
        let victim = self.cache.iter().next().map(|entry| *entry.key());
        let Some(victim) = victim else {
            return false;
        };
        if self.cache.remove(&victim).is_some() {
            self.release_cache_slot();
            true
        } else {
            false
        }
    }

    /// Connect to one directory endpoint with configured settings.
    ///
    /// A connection failure is a backend/infrastructure problem (directory
    /// unreachable, TLS handshake failure), not a credential problem, so it is
    /// surfaced as [`AuthError::Unavailable`] and the flow may fail over to the
    /// next configured endpoint.
    async fn connect(&self, endpoint: &LdapEndpoint) -> Result<Ldap, AuthError> {
        let deadline = tokio::time::Instant::now() + self.connect_timeout;
        tokio::time::timeout_at(deadline, self.connect_with_policy(endpoint, deadline))
            .await
            .map_err(|_| {
                AuthError::Unavailable(
                    "ldap_auth: DNS resolution or connection establishment timed out".to_string(),
                )
            })?
    }

    async fn connect_with_policy(
        &self,
        endpoint: &LdapEndpoint,
        deadline: tokio::time::Instant,
    ) -> Result<Ldap, AuthError> {
        let candidates = self
            .dns_cache
            .resolve_all_fresh(&endpoint.hostname)
            .await
            .map_err(|error| {
                AuthError::Unavailable(format!(
                    "ldap_auth: dial-time DNS resolution failed: {error}"
                ))
            })?;

        // Validate the complete answer set before opening any socket. A mixed
        // allowed/denied response fails closed instead of letting an allowed
        // decoy make the answer look safe while a client later selects a denied
        // candidate.
        for &candidate in &candidates {
            self.screen_dial_candidate(candidate)?;
        }

        let candidate_count = candidates.len();
        let mut last_failure = None;
        for (index, candidate) in candidates.into_iter().enumerate() {
            // Keep the active-policy check immediately adjacent to the actual
            // dial. This is intentionally repeated after the whole-set screen.
            self.screen_dial_candidate(candidate)?;
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            // Split what is left evenly across the candidates not yet tried,
            // so one address that accepts TCP and then stalls (or never
            // answers the SYN) cannot spend the budget a healthy replica
            // behind it needs. TLS/STARTTLS establishment is part of the
            // attempt, and a TLS failure moves on to the next candidate too.
            let untried = u32::try_from(candidate_count - index).unwrap_or(u32::MAX);
            let budget = remaining / untried.max(1);
            let socket_addr = SocketAddr::new(candidate, endpoint.port);
            match tokio::time::timeout(
                budget,
                self.connect_candidate(endpoint, socket_addr, budget),
            )
            .await
            {
                Ok(Ok(ldap)) => return Ok(ldap),
                Ok(Err(failure)) => last_failure = Some(failure),
                Err(_) => {
                    last_failure = Some(format!(
                        "connection establishment with {socket_addr} timed out"
                    ));
                }
            }
        }

        match last_failure {
            Some(failure) => Err(AuthError::Unavailable(format!(
                "ldap_auth: all screened connection candidates failed; last attempt: {failure}"
            ))),
            None => Err(AuthError::Unavailable(
                "ldap_auth: dial-time DNS resolution returned no connection candidates".to_string(),
            )),
        }
    }

    /// Dial one screened candidate and complete LDAP (and TLS/STARTTLS)
    /// establishment over it.
    async fn connect_candidate(
        &self,
        endpoint: &LdapEndpoint,
        socket_addr: SocketAddr,
        budget: Duration,
    ) -> Result<Ldap, String> {
        let stream = TcpStream::connect(socket_addr)
            .await
            .map_err(|error| format!("dial to {socket_addr} failed: {error}"))?;
        let std_stream = stream.into_std().map_err(|error| {
            format!("failed to prepare screened connection to {socket_addr}: {error}")
        })?;
        self.connect_ldap_over_stream(endpoint, std_stream, budget)
            .await
            .map_err(|error| format!("connection to {socket_addr} failed: {error}"))
    }

    fn screen_dial_candidate(&self, candidate: IpAddr) -> Result<(), AuthError> {
        if let Some(reason) = self.backend_egress_policy.deny_reason(&candidate) {
            return Err(AuthError::Unavailable(format!(
                "ldap_auth: dial candidate {candidate} denied by backend egress policy: {reason}"
            )));
        }
        if self.plaintext_requires_loopback && !candidate.is_loopback() {
            return Err(AuthError::Unavailable(format!(
                "ldap_auth: plaintext loopback endpoint resolved to non-loopback address {candidate}"
            )));
        }
        Ok(())
    }

    async fn connect_ldap_over_stream(
        &self,
        endpoint: &LdapEndpoint,
        stream: std::net::TcpStream,
        establishment_timeout: Duration,
    ) -> Result<Ldap, ldap3::LdapError> {
        let mut settings = LdapConnSettings::new()
            .set_conn_timeout(establishment_timeout)
            .set_starttls(self.starttls)
            .set_no_tls_verify(self.tls_no_verify)
            .set_std_stream(StdStream::Tcp(stream));

        if let Some(ref config) = self.tls_config {
            settings = settings.set_config(config.clone());
        }

        // Supplying the original URL together with the preconnected concrete
        // socket makes ldap3 use the endpoint hostname for rustls
        // ServerName/SNI. The screened IP is never substituted into the TLS
        // identity.
        let (conn, ldap) = LdapConnAsync::with_settings(settings, &endpoint.url).await?;

        // Drive the connection in the background
        ldap3::drive!(conn);

        Ok(ldap)
    }

    /// Lend a connection bound as the service account on `endpoint`.
    ///
    /// With `service_connection_max_age_seconds` unset every flow gets a fresh
    /// connection (fresh DNS answer and screened dial) that it unbinds when
    /// done. With it set, a connection younger than that age whose driver is
    /// still running is shared by concurrent searches; a new one is screened,
    /// dialed, and bound exactly like a fresh connection before it is shared.
    async fn service_connection<'a>(
        &self,
        endpoint: &'a LdapEndpoint,
        service_dn: &str,
        service_password: &str,
        context: &str,
    ) -> Result<ServiceConnection<'a>, AuthError> {
        let reuse = !self.service_connection_max_age.is_zero();
        if reuse && let Some(pooled) = endpoint.service_connection.load_full() {
            let mut ldap = pooled.ldap.clone();
            if pooled.created_at.elapsed() < self.service_connection_max_age && !ldap.is_closed() {
                return Ok(ServiceConnection {
                    ldap,
                    pooled: Some(pooled),
                    endpoint,
                    settled: false,
                });
            }
            endpoint.retire_service_connection(&pooled);
        }

        let mut ldap = self.connect(endpoint).await?;
        // A failed/rejected service-account bind is an operator
        // misconfiguration, never the end user's fault.
        let bind_result = ldap
            .with_timeout(self.connect_timeout)
            .simple_bind(service_dn, service_password)
            .await
            .map_err(|e| transport_error(context, e))?;
        if bind_result.rc != 0 {
            return Err(directory_result_error(&bind_result, context));
        }

        if !reuse {
            return Ok(ServiceConnection {
                ldap,
                pooled: None,
                endpoint,
                settled: false,
            });
        }
        let pooled = Arc::new(PooledServiceConnection {
            ldap: ldap.clone(),
            created_at: Instant::now(),
        });
        endpoint.service_connection.store(Some(Arc::clone(&pooled)));
        Ok(ServiceConnection {
            ldap,
            pooled: Some(pooled),
            endpoint,
            settled: false,
        })
    }

    /// Return a lent service-account connection. A private connection is
    /// unbound; a shared one is left open unless the flow failed on it at the
    /// transport level, in which case it is no longer handed out.
    async fn release_service_connection(
        &self,
        mut connection: ServiceConnection<'_>,
        error: Option<&AuthError>,
    ) {
        // The operation finished: from here a cancellation (for example during
        // the unbind below) has nothing outstanding to clean up.
        connection.settled = true;
        match connection.pooled.as_ref() {
            Some(pooled) => {
                if matches!(error, Some(AuthError::Unavailable(_))) {
                    connection.endpoint.retire_service_connection(pooled);
                }
            }
            None => {
                let _ = connection
                    .ldap
                    .with_timeout(self.connect_timeout)
                    .unbind()
                    .await;
            }
        }
    }

    /// Authenticate against each configured endpoint in order until one
    /// answers. Only [`AuthError::Unavailable`] moves on: a credential
    /// rejection or a configuration/directory error is final.
    async fn authenticate_user_with_failover(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthenticatedUser, AuthError> {
        let mut last_unavailable = None;
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            match self.authenticate_user(endpoint, username, password).await {
                Err(AuthError::Unavailable(message)) => {
                    if index + 1 < self.endpoints.len() {
                        warn!("{message}; trying the next configured directory endpoint");
                    }
                    last_unavailable = Some(message);
                }
                outcome => return outcome,
            }
        }
        Err(AuthError::Unavailable(last_unavailable.unwrap_or_else(
            || "ldap_auth: no directory endpoint is configured".to_string(),
        )))
    }

    /// [`Self::check_group_membership`] with the same endpoint failover as
    /// [`Self::authenticate_user_with_failover`].
    async fn check_group_membership_with_failover(
        &self,
        user_dn: &str,
        canonical_identity: &str,
        member_of_proofs_remaining: &mut usize,
    ) -> Result<bool, AuthError> {
        let mut last_unavailable = None;
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            match self
                .check_group_membership(
                    endpoint,
                    user_dn,
                    canonical_identity,
                    member_of_proofs_remaining,
                )
                .await
            {
                Err(AuthError::Unavailable(message)) => {
                    if index + 1 < self.endpoints.len() {
                        warn!("{message}; trying the next configured directory endpoint");
                    }
                    last_unavailable = Some(message);
                }
                outcome => return outcome,
            }
        }
        Err(AuthError::Unavailable(last_unavailable.unwrap_or_else(
            || "ldap_auth: no directory endpoint is configured".to_string(),
        )))
    }

    /// Authenticate a user against one endpoint via direct bind or
    /// search-then-bind. Returns the user's DN and canonical Ferrum identity on
    /// success.
    ///
    /// Errors are classified ([`AuthError`]) so that a rejected user bind /
    /// "user not found" surfaces as a 401 while a directory outage, a failed
    /// service-account bind, or a search RPC error surfaces as a 500 (finding
    /// #32). A bind that *fails* (transport / RPC error) is a backend problem;
    /// a bind that is *rejected* (LDAP returned a non-success result code for
    /// the end user's credentials) is the genuine invalid-credential case.
    async fn authenticate_user(
        &self,
        endpoint: &LdapEndpoint,
        username: &str,
        password: &str,
    ) -> Result<AuthenticatedUser, AuthError> {
        if let Some(ref template) = self.bind_dn_template {
            let mut ldap = self.connect(endpoint).await?;
            // Direct bind: substitute DN-escaped username into template (RFC 4514)
            let dn = template.replace("{username}", &escape_dn_value(username));
            let bind_result = ldap
                .with_timeout(self.connect_timeout)
                .simple_bind(&dn, password)
                .await
                .map_err(|e| transport_error("bind", e))?;
            classify_user_bind_result(bind_result, "bind")?;

            // The presented login is not an identity. Directories match and fold
            // login attributes case- and whitespace-insensitively, so one
            // account would otherwise mint an unbounded set of distinct Ferrum
            // principals. Read the canonical attribute off the entry that
            // actually authenticated, over that entry's own bound connection,
            // exactly as search-then-bind does.
            let canonical_identity = self.read_canonical_identity(&mut ldap, &dn).await?;
            let _ = ldap.with_timeout(self.connect_timeout).unbind().await;
            return Ok(AuthenticatedUser {
                dn,
                canonical_identity,
            });
        }

        // Search-then-bind: find user DN via service account
        let service_dn = self.service_account_dn.as_deref().unwrap_or_default();
        let service_pw = self.service_account_password.as_deref().unwrap_or_default();
        let mut service = self
            .service_connection(endpoint, service_dn, service_pw, "service account bind")
            .await?;
        let search = self.search_user_entry(&mut service.ldap, username).await;
        self.release_service_connection(service, search.as_ref().err())
            .await;
        let Some(found) = search? else {
            let search_base = self.search_base_dn.as_deref().unwrap_or_default();
            self.equalize_unknown_user_bind(endpoint, search_base)
                .await?;
            return Err(AuthError::Credential(
                "ldap_auth: user not found".to_string(),
            ));
        };

        // Bind as the user on a connection of its own: an end-user bind never
        // touches a shared service-account connection.
        let mut user_ldap = self.connect(endpoint).await?;
        let user_bind_result = user_ldap
            .with_timeout(self.connect_timeout)
            .simple_bind(&found.dn, password)
            .await
            .map_err(|e| transport_error("user bind", e))?;
        classify_user_bind_result(user_bind_result, "user bind")?;

        let _ = user_ldap.with_timeout(self.connect_timeout).unbind().await;
        Ok(found)
    }

    /// Run the configured user search over a service-account connection.
    /// `Ok(None)` means no entry matched.
    async fn search_user_entry(
        &self,
        ldap: &mut Ldap,
        username: &str,
    ) -> Result<Option<AuthenticatedUser>, AuthError> {
        let search_base = self.search_base_dn.as_deref().unwrap_or_default();
        let filter = self
            .search_filter
            .as_deref()
            .unwrap_or_default()
            .replace("{username}", &escape_filter_value(username));
        let canonical_identity_attribute = self
            .canonical_identity_attribute
            .as_deref()
            .ok_or_else(|| {
                AuthError::Backend(
                    "ldap_auth: canonical identity attribute is missing in search-then-bind mode"
                        .to_string(),
                )
            })?;

        let search_result = ldap
            .with_search_options(
                SearchOptions::new()
                    .sizelimit(LDAP_AUTH_USER_SEARCH_SIZE_LIMIT)
                    .timelimit(self.search_time_limit_seconds),
            )
            .with_timeout(self.connect_timeout)
            // The DN is part of every LDAP search result, not a regular
            // attribute. Request only the configured canonical identity
            // attribute; `SearchEntry::dn` still carries the bind target.
            .search(
                search_base,
                Scope::Subtree,
                &filter,
                vec![canonical_identity_attribute],
            )
            .await
            .map_err(|e| transport_error("user search", e))?;

        if search_result.1.rc == 4 && search_result.0.len() >= 2 {
            return Err(AuthError::Credential(
                "ldap_auth: user search was ambiguous".to_string(),
            ));
        }
        if search_result.1.rc != 0 {
            return Err(directory_result_error(&search_result.1, "user search"));
        }

        let mut entries = search_result.0;
        let result_entry = match entries.len() {
            0 => return Ok(None),
            1 => entries.pop().ok_or_else(|| {
                AuthError::Backend(
                    "ldap_auth: user result disappeared after uniqueness check".to_string(),
                )
            })?,
            _ => {
                return Err(AuthError::Credential(
                    "ldap_auth: user search was ambiguous".to_string(),
                ));
            }
        };
        let entry = SearchEntry::construct(result_entry);
        let canonical_identity = unique_ldap_attribute_value(
            &entry.attrs,
            canonical_identity_attribute,
            "canonical identity",
        )?
        .ok_or_else(|| {
            AuthError::Backend(format!(
                "ldap_auth: user search result is missing canonical identity attribute '{canonical_identity_attribute}'"
            ))
        })?;
        Ok(Some(AuthenticatedUser {
            dn: entry.dn,
            canonical_identity,
        }))
    }

    /// Spend the gateway-side work a known user's failed bind costs (a fresh
    /// connection and one simple bind round trip) when search-then-bind finds
    /// no entry, so the extra round trips no longer reveal which usernames
    /// exist (issue #6609). Directory-side cost can still differ: a directory
    /// may verify an expensive password hash only for an existing entry.
    ///
    /// The bind targets a fresh random RDN under `search_base_dn` with a random
    /// throwaway password: the client's password never leaves for a DN it did
    /// not authenticate against, and no real entry is targeted repeatedly.
    ///
    /// Infrastructure failures are classified exactly like the real user bind
    /// (500, after endpoint failover), so an unreachable or unavailable directory
    /// answers an unknown and a known username the same way. Only a credential
    /// rejection (or an unexpected success) of the throwaway bind becomes the
    /// ordinary "user not found" 401.
    async fn equalize_unknown_user_bind(
        &self,
        endpoint: &LdapEndpoint,
        search_base: &str,
    ) -> Result<(), AuthError> {
        let mut random = [0u8; 40];
        crate::fips::backend::rand::SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| {
                AuthError::Backend("ldap_auth: failed to generate equalizer bind".to_string())
            })?;
        let (rdn_suffix, password_bytes) = random.split_at(16);
        let rdn_suffix: String = rdn_suffix
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let throwaway_password = base64::engine::general_purpose::STANDARD.encode(password_bytes);
        let equalizer_dn = if search_base.is_empty() {
            format!("{LDAP_AUTH_UNKNOWN_USER_EQUALIZER_RDN_PREFIX}{rdn_suffix}")
        } else {
            format!("{LDAP_AUTH_UNKNOWN_USER_EQUALIZER_RDN_PREFIX}{rdn_suffix},{search_base}")
        };
        let mut ldap = self.connect(endpoint).await?;
        let bind_result = ldap
            .with_timeout(self.connect_timeout)
            .simple_bind(&equalizer_dn, &throwaway_password)
            .await
            .map_err(|e| transport_error("user bind", e));
        let _ = ldap.with_timeout(self.connect_timeout).unbind().await;
        match classify_user_bind_result(bind_result?, "user bind") {
            Ok(()) | Err(AuthError::Credential(_)) => Ok(()),
            Err(backend) => Err(backend),
        }
    }

    /// Read the configured canonical identity attribute off an already
    /// authenticated entry with a base-scope search on that entry's own DN.
    ///
    /// Used by direct bind, where the presented login never becomes the Ferrum
    /// identity. Failures are never credential failures: the credentials were
    /// already accepted, so an unreadable or ambiguous canonical value is a
    /// directory/configuration problem (500), and the flow fails closed rather
    /// than falling back to the client-supplied string.
    async fn read_canonical_identity(
        &self,
        ldap: &mut Ldap,
        entry_dn: &str,
    ) -> Result<String, AuthError> {
        let Some(attribute) = self.canonical_identity_attribute.as_deref() else {
            return Err(AuthError::Backend(
                "ldap_auth: canonical identity attribute is missing in direct-bind mode"
                    .to_string(),
            ));
        };

        let search_result = ldap
            .with_search_options(
                SearchOptions::new()
                    .sizelimit(LDAP_AUTH_USER_SEARCH_SIZE_LIMIT)
                    .timelimit(self.search_time_limit_seconds),
            )
            .with_timeout(self.connect_timeout)
            .search(entry_dn, Scope::Base, "(objectClass=*)", vec![attribute])
            .await
            .map_err(|e| transport_error("canonical identity search", e))?;
        if search_result.1.rc != 0 {
            return Err(directory_result_error(
                &search_result.1,
                "canonical identity search",
            ));
        }
        let entries = search_result.0;

        let result_entry = match entries.len() {
            0 => {
                return Err(AuthError::Backend(
                    "ldap_auth: the bound entry returned no canonical identity result".to_string(),
                ));
            }
            1 => entries.into_iter().next().ok_or_else(|| {
                AuthError::Backend(
                    "ldap_auth: canonical identity entry disappeared after uniqueness check"
                        .to_string(),
                )
            })?,
            _ => {
                return Err(AuthError::Backend(
                    "ldap_auth: base-scope canonical identity search returned multiple entries"
                        .to_string(),
                ));
            }
        };

        let entry = SearchEntry::construct(result_entry);
        let canonical_identity =
            unique_ldap_attribute_value(&entry.attrs, attribute, "canonical identity")?;
        canonical_identity.ok_or_else(|| {
            AuthError::Backend(format!(
                "ldap_auth: the bound entry is missing canonical identity attribute '{attribute}'"
            ))
        })
    }

    /// Check, against one endpoint, whether the authenticated user belongs to
    /// at least one of the required groups.
    ///
    /// Connection, bind, and search failures are backend/infrastructure
    /// problems ([`AuthError::Backend`] / [`AuthError::Unavailable`]) → 500. A
    /// successful search that simply matches no group is `Ok(false)` (the user
    /// is genuinely not entitled → 403).
    async fn check_group_membership(
        &self,
        endpoint: &LdapEndpoint,
        user_dn: &str,
        canonical_identity: &str,
        member_of_proofs_remaining: &mut usize,
    ) -> Result<bool, AuthError> {
        if self.required_groups.is_empty() {
            return Ok(true);
        }
        // Every filter value the plugin interpolates is bounded, whatever the
        // directory returned for the authenticated entry.
        if user_dn.len() > LDAP_AUTH_MAX_FILTER_VALUE_BYTES
            || canonical_identity.len() > LDAP_AUTH_MAX_FILTER_VALUE_BYTES
        {
            return Err(AuthError::Backend(format!(
                "ldap_auth: the authenticated DN or canonical identity exceeds {LDAP_AUTH_MAX_FILTER_VALUE_BYTES} bytes and cannot be used in a group-membership filter"
            )));
        }

        // Bind with the service account when one is configured; otherwise the
        // group search runs over an ANONYMOUS-bound connection. Many directories
        // deny or restrict anonymous reads of group `member` attributes, in
        // which case the search returns zero entries and a legitimately
        // entitled user is wrongly denied (403). Operators are warned at
        // startup (see `new()`) when group enforcement relies on anonymous
        // search; finding #33.
        let (mut connection, used_service_account) = if let (Some(dn), Some(pw)) =
            (&self.service_account_dn, &self.service_account_password)
        {
            (
                self.service_connection(endpoint, dn, pw, "group check bind")
                    .await?,
                true,
            )
        } else {
            (
                ServiceConnection {
                    ldap: self.connect(endpoint).await?,
                    pooled: None,
                    endpoint,
                    settled: false,
                },
                false,
            )
        };
        let membership = if self.group_membership_mode == GroupMembershipMode::MemberOf {
            self.search_member_of_groups(
                &mut connection.ldap,
                user_dn,
                used_service_account,
                member_of_proofs_remaining,
            )
            .await
        } else {
            let filter = self.group_search_filter(user_dn, canonical_identity);
            self.search_required_groups(
                &mut connection.ldap,
                &filter,
                user_dn,
                canonical_identity,
                used_service_account,
            )
            .await
        };
        self.release_service_connection(connection, membership.as_ref().err())
            .await;
        membership
    }

    async fn search_required_groups(
        &self,
        ldap: &mut Ldap,
        filter: &str,
        user_dn: &str,
        canonical_identity: &str,
        used_service_account: bool,
    ) -> Result<bool, AuthError> {
        let group_base = self.group_base_dn.as_deref().unwrap_or_default();
        let search_result = ldap
            .with_search_options(
                SearchOptions::new()
                    .sizelimit(LDAP_AUTH_GROUP_SEARCH_SIZE_LIMIT)
                    .timelimit(self.search_time_limit_seconds),
            )
            .with_timeout(self.connect_timeout)
            .search(
                group_base,
                Scope::Subtree,
                filter,
                vec![self.group_attribute.as_str()],
            )
            .await
            .map_err(|e| transport_error("group search", e))?;

        let result_code = search_result.1.rc;
        if result_code != 0 && result_code != 4 {
            return Err(directory_result_error(&search_result.1, "group search"));
        }
        let size_limit_exceeded = result_code == 4;
        let rs = search_result.0;

        // A zero-entry result is ambiguous: the user may genuinely belong to no
        // group, OR the directory may have silently returned nothing because an
        // anonymous (no service account) search of group objects is restricted
        // by directory ACLs. Surface that distinction so operators can tell an
        // entitlement denial from a misconfigured search permission (finding #33).
        if rs.is_empty() && !used_service_account {
            warn!(
                "ldap_auth: group search for user '{}' under '{}' returned no entries over an \
                 anonymous bind; this is either a genuine no-membership result or the directory \
                 restricts anonymous reads of group objects — configure 'service_account_dn'/\
                 'service_account_password' if groups are not being matched",
                canonical_identity, group_base
            );
        }

        for result_entry in rs {
            let entry = SearchEntry::construct(result_entry);
            if !self.entry_matches_required_group(&entry)? {
                continue;
            }

            // The built-in filter itself is the membership proof. A custom
            // filter may contain static branches that also return this group,
            // so re-check the exact returned entry with a server-side,
            // schema-aware membership predicate before authorizing it.
            if self.group_filter.is_none()
                || self
                    .returned_group_proves_membership(ldap, &entry.dn, user_dn, canonical_identity)
                    .await?
            {
                return Ok(true);
            }
        }

        if size_limit_exceeded {
            return Err(AuthError::Backend(
                "ldap_auth: group search exceeded the configured size limit before proving required membership"
                    .to_string(),
            ));
        }

        Ok(false)
    }

    fn group_search_filter(&self, user_dn: &str, canonical_identity: &str) -> String {
        // Group authorization must use the authenticated account identity, not
        // the client-presented login value, which may be an alias or a
        // case/whitespace variant of the directory entry's own attribute.
        match self.group_filter.as_ref() {
            Some(filter) => {
                let mut resolved_filter = filter.clone();
                if filter.contains("{user_dn}") {
                    let escaped_user_dn = escape_filter_value(user_dn);
                    resolved_filter = resolved_filter.replace("{user_dn}", &escaped_user_dn);
                }
                if filter.contains("{username}") {
                    let escaped_identity = escape_filter_value(canonical_identity);
                    resolved_filter = resolved_filter.replace("{username}", &escaped_identity);
                }
                resolved_filter
            }
            None => group_membership_filter(
                self.group_membership_mode,
                self.group_member_attribute.as_deref(),
                user_dn,
                canonical_identity,
            ),
        }
    }

    /// Whether a returned group entry is one of `required_groups`.
    ///
    /// The configured `group_attribute` is authoritative: when the directory
    /// returns it, only its values decide, and a present but non-matching
    /// value rejects the entry. Directories permit equal RDNs in different
    /// containers (Active Directory allows a second `CN=gateway-admins` in any
    /// OU whose writer can create groups), while an attribute such as
    /// `sAMAccountName` is unique, so falling back to the RDN after an
    /// explicit mismatch would let a look-alike group satisfy the gate.
    ///
    /// Only when the directory omits the attribute AND it is `cn` — the one
    /// group-naming attribute every group's RDN conventionally carries — does
    /// the entry's OWN first RDN stand in for it, and then only a `cn`-typed
    /// component. Any other configured attribute that the directory omits
    /// fails closed as a non-match.
    fn entry_matches_required_group(&self, entry: &SearchEntry) -> Result<bool, AuthError> {
        if let Some(group_names) =
            ldap_attribute_values(&entry.attrs, &self.group_attribute, "group")?
        {
            return Ok(group_names.iter().any(|name| {
                self.required_group_lookup
                    .contains(&prepare_case_ignore(name))
            }));
        }

        if !self.group_attribute.eq_ignore_ascii_case("cn") {
            return Ok(false);
        }

        // Only the first RDN may name the entry: scanning the whole DN for a
        // `cn=` component would let `uid=visitors,cn=admins,ou=groups,...` — an
        // entry merely nested UNDER a required group — satisfy the `admins`
        // gate, and a naive comma split would do the same for an RDN whose
        // value contains an escaped comma (`ou=visitors\,cn=admins,...`).
        // Whoever can create or name entries under `group_base_dn` would
        // otherwise mint gateway group membership without touching the real
        // group object.
        let Some(rdn) = parse_first_rdn(&entry.dn) else {
            return Ok(false);
        };
        Ok(rdn.iter().any(|ava| {
            ava.attribute_type.eq_ignore_ascii_case("cn")
                && self
                    .required_group_lookup
                    .contains(&prepare_case_ignore(&ava.value))
        }))
    }

    /// `member_of` mode: find the required groups under `group_base_dn` by
    /// their authoritative `group_attribute` value, then let the directory
    /// prove, with a base-scope equality search on the authenticated entry,
    /// that its reverse-membership attribute lists that exact group DN.
    ///
    /// The DN comparison is the directory's own `distinguishedNameMatch`, so
    /// each naming attribute keeps its schema equality rule (a
    /// `caseExactMatch` naming attribute stays case-sensitive). The plugin
    /// never compares DNs itself. A look-alike group elsewhere or a group the
    /// entry does not list never matches.
    async fn search_member_of_groups(
        &self,
        ldap: &mut Ldap,
        user_dn: &str,
        used_service_account: bool,
        member_of_proofs_remaining: &mut usize,
    ) -> Result<bool, AuthError> {
        let attribute = self
            .group_member_attribute
            .as_deref()
            .unwrap_or(LDAP_AUTH_DEFAULT_MEMBER_OF_ATTRIBUTE);
        let Some(filter) = self.member_of_group_filter.as_deref() else {
            return Ok(false);
        };
        let group_base = self.group_base_dn.as_deref().unwrap_or_default();
        let search_result = ldap
            .with_search_options(
                SearchOptions::new()
                    .sizelimit(LDAP_AUTH_GROUP_SEARCH_SIZE_LIMIT)
                    .timelimit(self.search_time_limit_seconds),
            )
            .with_timeout(self.connect_timeout)
            .search(
                group_base,
                Scope::Subtree,
                filter,
                vec![self.group_attribute.as_str()],
            )
            .await
            .map_err(|e| transport_error("group search", e))?;
        let result_code = search_result.1.rc;
        if result_code != 0 && result_code != 4 {
            return Err(directory_result_error(&search_result.1, "group search"));
        }

        let mut found_candidate = false;
        let mut unproven_candidates = false;
        for result_entry in search_result.0 {
            let entry = SearchEntry::construct(result_entry);
            if !self.entry_matches_required_group(&entry)? {
                continue;
            }
            found_candidate = true;
            if *member_of_proofs_remaining == 0 {
                unproven_candidates = true;
                break;
            }
            // Charge before awaiting: unavailable endpoints and cancelled
            // cached re-checks cannot restore a proof already attempted.
            *member_of_proofs_remaining -= 1;
            if self
                .user_entry_lists_group(ldap, user_dn, attribute, &entry.dn)
                .await?
            {
                return Ok(true);
            }
        }
        if !found_candidate && !used_service_account {
            warn!(
                "ldap_auth: no required group was found under '{}' over an anonymous bind; configure a service account if the directory restricts group reads",
                group_base
            );
        }
        if result_code == 4 || unproven_candidates {
            return Err(AuthError::Backend(
                "ldap_auth: group search exceeded the configured limits before proving required membership"
                    .to_string(),
            ));
        }
        Ok(false)
    }

    /// Base-scope `(<attribute>=<group DN>)` search on the authenticated entry:
    /// the directory, not the plugin, decides whether the entry lists that DN.
    async fn user_entry_lists_group(
        &self,
        ldap: &mut Ldap,
        user_dn: &str,
        attribute: &str,
        group_dn: &str,
    ) -> Result<bool, AuthError> {
        if group_dn.len() > LDAP_AUTH_MAX_FILTER_VALUE_BYTES {
            return Ok(false);
        }
        let proof_filter = format!("({attribute}={})", escape_filter_value(group_dn));
        let search_result = ldap
            .with_search_options(
                SearchOptions::new()
                    .sizelimit(1)
                    .timelimit(self.search_time_limit_seconds),
            )
            .with_timeout(self.connect_timeout)
            .search(user_dn, Scope::Base, &proof_filter, vec!["1.1"])
            .await
            .map_err(|e| transport_error("group membership verification", e))?;
        if search_result.1.rc != 0 {
            return Err(directory_result_error(
                &search_result.1,
                "group membership verification",
            ));
        }
        match search_result.0.len() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AuthError::Backend(
                "ldap_auth: base-scope group membership verification returned multiple entries"
                    .to_string(),
            )),
        }
    }

    async fn returned_group_proves_membership(
        &self,
        ldap: &mut Ldap,
        group_dn: &str,
        user_dn: &str,
        canonical_identity: &str,
    ) -> Result<bool, AuthError> {
        let membership_filter = group_membership_filter(
            self.group_membership_mode,
            self.group_member_attribute.as_deref(),
            user_dn,
            canonical_identity,
        );
        let search_result = ldap
            .with_search_options(
                SearchOptions::new()
                    .sizelimit(1)
                    .timelimit(self.search_time_limit_seconds),
            )
            .with_timeout(self.connect_timeout)
            .search(group_dn, Scope::Base, &membership_filter, vec!["1.1"])
            .await
            .map_err(|e| transport_error("returned group membership verification", e))?;
        if search_result.1.rc != 0 {
            return Err(directory_result_error(
                &search_result.1,
                "returned group membership verification",
            ));
        }

        match search_result.0.len() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AuthError::Backend(
                "ldap_auth: base-scope group membership verification returned multiple entries"
                    .to_string(),
            )),
        }
    }
}

/// The server-side predicate that proves a group entry lists the user.
///
/// - `direct` without `group_member_attribute`: `member` / `uniqueMember`
///   (user DN) or `memberUid` (canonical identity).
/// - `direct` with `group_member_attribute`: that DN-valued attribute.
/// - `ad_in_chain`: [`LDAP_MATCHING_RULE_IN_CHAIN_OID`] on
///   `group_member_attribute` (default `member`), so Active Directory
///   evaluates nested membership itself, bounded by the search size and time
///   limits.
///
/// Attribute names are validated descriptors at admission, and both values
/// are RFC 4515-escaped.
fn group_membership_filter(
    mode: GroupMembershipMode,
    member_attribute: Option<&str>,
    user_dn: &str,
    canonical_identity: &str,
) -> String {
    let escaped_user_dn = escape_filter_value(user_dn);
    match (mode, member_attribute) {
        // `member_of` never sends a group-side predicate (it proves
        // membership from the user's own entry); it shares the direct default
        // only so this function stays total.
        (GroupMembershipMode::Direct | GroupMembershipMode::MemberOf, None) => {
            let escaped_identity = escape_filter_value(canonical_identity);
            format!(
                "(|(member={escaped_user_dn})(uniqueMember={escaped_user_dn})(memberUid={escaped_identity}))"
            )
        }
        (GroupMembershipMode::Direct | GroupMembershipMode::MemberOf, Some(attribute)) => {
            format!("({attribute}={escaped_user_dn})")
        }
        (GroupMembershipMode::AdInChain, attribute) => {
            let attribute = attribute.unwrap_or("member");
            format!("({attribute}:{LDAP_MATCHING_RULE_IN_CHAIN_OID}:={escaped_user_dn})")
        }
    }
}

fn ldap_attribute_values<'a>(
    attrs: &'a HashMap<String, Vec<String>>,
    attribute: &str,
    purpose: &str,
) -> Result<Option<&'a Vec<String>>, AuthError> {
    let mut match_values = None;
    for (name, values) in attrs {
        if name.eq_ignore_ascii_case(attribute) {
            if match_values.is_some() {
                return Err(AuthError::Backend(format!(
                    "ldap_auth: directory returned duplicate case-variant {purpose} attributes for '{attribute}'"
                )));
            }
            match_values = Some(values);
        }
    }
    Ok(match_values)
}

fn unique_ldap_attribute_value(
    attrs: &HashMap<String, Vec<String>>,
    attribute: &str,
    purpose: &str,
) -> Result<Option<String>, AuthError> {
    let Some(values) = ldap_attribute_values(attrs, attribute, purpose)? else {
        return Ok(None);
    };
    if values.len() != 1 {
        return Err(AuthError::Backend(format!(
            "ldap_auth: directory must return exactly one {purpose} value for '{attribute}'"
        )));
    }
    let Some(value) = values.first() else {
        return Err(AuthError::Backend(format!(
            "ldap_auth: directory returned no {purpose} value for '{attribute}'"
        )));
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(AuthError::Backend(format!(
            "ldap_auth: directory returned an empty {purpose} value for '{attribute}'"
        )));
    }
    Ok(Some(value.to_string()))
}

fn reject_unknown_config_keys(config: &Map<String, Value>) -> Result<(), String> {
    if config.contains_key("consumer_mapping") {
        return Err("ldap_auth: `consumer_mapping` was removed; see the upgrade guide".to_string());
    }

    const KNOWN_KEYS: &[&str] = &[
        "ldap_url",
        "failover_ldap_urls",
        "bind_dn_template",
        "search_base_dn",
        "search_filter",
        "canonical_identity_attribute",
        "service_account_dn",
        "service_account_password",
        "group_base_dn",
        "group_filter",
        "required_groups",
        "group_attribute",
        "group_member_attribute",
        "group_membership_mode",
        "starttls",
        "allow_plaintext",
        "connect_timeout_seconds",
        "request_timeout_seconds",
        "max_concurrent_requests",
        "cache_ttl_seconds",
        "group_cache_ttl_seconds",
        "max_cache_entries",
        "negative_cache_ttl_seconds",
        "max_failed_attempts_per_user",
        "failed_attempt_backoff_seconds",
        "service_connection_max_age_seconds",
        "hide_credentials",
    ];
    for key in config.keys() {
        if !KNOWN_KEYS.contains(&key.as_str()) {
            return Err(format!("ldap_auth: unknown config key {key:?}"));
        }
    }
    Ok(())
}

fn parse_required_ldap_url(config: &Map<String, Value>) -> Result<&str, String> {
    let Some(value) = config.get("ldap_url") else {
        return Err(
            "ldap_auth: `ldap_url` is required (e.g. `ldap://ldap.example.com:389` or `ldaps://ldap.example.com:636`)"
                .to_string(),
        );
    };
    value.as_str().ok_or_else(|| {
        format!(
            "ldap_auth: `ldap_url` must be a string, got: {value:?}",
            value = value.to_string()
        )
    })
}

/// One parsed `ldap://` / `ldaps://` endpoint value.
struct ParsedLdapUrl {
    /// Config field the value came from, for diagnostics.
    field: String,
    url: String,
    parsed: Url,
    is_ldaps: bool,
    hostname: String,
    port: u16,
}

/// Parse and validate one directory URL (`ldap_url` or a
/// `failover_ldap_urls` entry). Diagnostics name the field, never the value.
fn parse_ldap_url_value(raw: &str, field: &str) -> Result<ParsedLdapUrl, String> {
    if raw.is_empty() {
        return Err(format!("ldap_auth: `{field}` must not be empty"));
    }
    // Trimming here would admit a padded value that `openapi.yaml` rejects and
    // that no directory URL legitimately carries.
    if raw.trim() != raw {
        return Err(format!(
            "ldap_auth: `{field}` must not have leading or trailing whitespace"
        ));
    }
    let parsed =
        Url::parse(raw).map_err(|e| format!("ldap_auth: `{field}` is not a valid URL: {e}"))?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!(
            "ldap_auth: `{field}` must not contain embedded credentials; use the service account fields"
        ));
    }

    // Decide the scheme from the RAW value, not from `Url::parse`, which
    // case-folds it: the published contract (and every `ldap_url` pattern
    // in `openapi.yaml`) is a lowercase scheme, so `LDAP://` must be
    // refused here rather than silently admitted by the gateway and
    // rejected by schema validation.
    let is_ldaps = if raw.starts_with("ldaps://") {
        true
    } else if raw.starts_with("ldap://") {
        false
    } else {
        return Err(format!(
            "ldap_auth: `{field}` must start with `ldap://` or `ldaps://`"
        ));
    };
    if !has_non_empty_authority(raw) {
        return Err(format!("ldap_auth: `{field}` must include a hostname"));
    }
    let hostname = ldap_url_hostname(&parsed, field)?;
    // Port 0 can never be dialed; admitting it would turn every request on the
    // route into a 500.
    let port = match parsed.port() {
        Some(0) => {
            return Err(format!(
                "ldap_auth: `{field}` port must be between 1 and 65535"
            ));
        }
        Some(port) => port,
        None if is_ldaps => 636,
        None => 389,
    };
    Ok(ParsedLdapUrl {
        field: field.to_string(),
        url: raw.to_string(),
        parsed,
        is_ldaps,
        hostname,
        port,
    })
}

/// Parse `failover_ldap_urls`: further directory endpoints tried in order
/// after `ldap_url`.
fn parse_failover_ldap_urls(config: &Map<String, Value>) -> Result<Vec<ParsedLdapUrl>, String> {
    let Some(value) = config.get("failover_ldap_urls") else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| "ldap_auth: `failover_ldap_urls` must be an array of strings".to_string())?;
    if items.is_empty() {
        return Err("ldap_auth: `failover_ldap_urls` must not be empty when set".to_string());
    }
    if items.len() > LDAP_AUTH_MAX_FAILOVER_URLS {
        return Err(format!(
            "ldap_auth: `failover_ldap_urls` must not list more than {LDAP_AUTH_MAX_FAILOVER_URLS} endpoints"
        ));
    }
    let mut endpoints: Vec<ParsedLdapUrl> = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let field = format!("failover_ldap_urls[{index}]");
        let raw = item
            .as_str()
            .ok_or_else(|| format!("ldap_auth: `{field}` must be a string"))?;
        let endpoint = parse_ldap_url_value(raw, &field)?;
        if endpoints.iter().any(|earlier| earlier.url == endpoint.url) {
            return Err(format!(
                "ldap_auth: `{field}` repeats an earlier `failover_ldap_urls` entry"
            ));
        }
        endpoints.push(endpoint);
    }
    Ok(endpoints)
}

fn is_loopback_ldap_endpoint(parsed: &Url) -> bool {
    match parsed.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(hostname)) => {
            let hostname = hostname.trim_end_matches('.');
            hostname
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
                || hostname.eq_ignore_ascii_case("localhost")
                || hostname.to_ascii_lowercase().ends_with(".localhost")
        }
        None => false,
    }
}

fn ldap_url_hostname(parsed: &Url, field: &str) -> Result<String, String> {
    let host = parsed
        .host()
        .ok_or_else(|| format!("ldap_auth: `{field}` must include a hostname"))?;

    Ok(match host {
        Host::Domain(hostname) => hostname.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    })
}

fn has_non_empty_authority(ldap_url: &str) -> bool {
    let Some((_, after_scheme)) = ldap_url.split_once(':') else {
        return false;
    };
    let Some(authority_and_path) = after_scheme.strip_prefix("//") else {
        return false;
    };
    let authority_end = authority_and_path
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_path.len());

    authority_end > 0
}

fn parse_optional_string(
    config: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let raw = value.as_str().ok_or_else(|| {
        format!(
            "ldap_auth: `{field}` must be a string, got: {value:?}",
            value = value.to_string()
        )
    })?;
    let value = raw.trim();
    if value.is_empty() {
        return Err(format!("ldap_auth: `{field}` must not be empty"));
    }
    Ok(Some(value.to_string()))
}

/// Parse a secret config value VERBATIM.
///
/// A password is an opaque string the directory compares byte for byte, so it
/// is never trimmed the way [`parse_optional_string`] trims identifiers:
/// silently dropping surrounding whitespace would make a legitimate secret
/// fail every service-account bind and surface as a directory outage (`500`)
/// rather than as a configuration error. Only a genuinely empty value is
/// rejected — an empty simple-bind password requests an anonymous bind.
fn parse_optional_secret_string(
    config: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let raw = value
        .as_str()
        .ok_or_else(|| format!("ldap_auth: `{field}` must be a string"))?;
    if raw.is_empty() {
        return Err(format!("ldap_auth: `{field}` must not be empty"));
    }
    Ok(Some(raw.to_string()))
}

fn parse_bool(
    config: &Map<String, Value>,
    field: &str,
    default_value: bool,
) -> Result<bool, String> {
    let Some(value) = config.get(field) else {
        return Ok(default_value);
    };
    value.as_bool().ok_or_else(|| {
        format!(
            "ldap_auth: `{field}` must be a boolean, got: {value:?}",
            value = value.to_string()
        )
    })
}

fn parse_u64(config: &Map<String, Value>, field: &str, default_value: u64) -> Result<u64, String> {
    let Some(value) = config.get(field) else {
        return Ok(default_value);
    };
    value.as_u64().ok_or_else(|| {
        format!(
            "ldap_auth: `{field}` must be an unsigned integer, got: {value:?}",
            value = value.to_string()
        )
    })
}

fn parse_usize(
    config: &Map<String, Value>,
    field: &str,
    default_value: usize,
) -> Result<usize, String> {
    let raw = parse_u64(config, field, default_value as u64)?;
    usize::try_from(raw).map_err(|_| format!("ldap_auth: `{field}` is too large"))
}

fn parse_string_array(config: &Map<String, Value>, field: &str) -> Result<Vec<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(Vec::new());
    };
    let arr = value.as_array().ok_or_else(|| {
        format!(
            "ldap_auth: `{field}` must be an array of strings, got: {value:?}",
            value = value.to_string()
        )
    })?;
    arr.iter()
        .map(|item| {
            let raw = item.as_str().ok_or_else(|| {
                format!(
                    "ldap_auth: `{field}` entries must be strings, got: {item:?}",
                    item = item.to_string()
                )
            })?;
            let value = raw.trim();
            if value.is_empty() {
                return Err(format!("ldap_auth: `{field}` entries must not be empty"));
            }
            Ok(value.to_string())
        })
        .collect()
}

/// Build a rustls `ClientConfig` for LDAP connections.
///
/// Integrates with gateway TLS settings while honouring the project-wide
/// "CA exclusivity" rule (CLAUDE.md "TLS Architecture"):
///
/// - `FERRUM_TLS_CA_BUNDLE_PATH` set: builds the trust store from
///   `RootCertStore::empty()` and adds ONLY the PEM certs from this bundle.
///   The system / webpki public-CA roots are NOT trusted, so a
///   public-CA-issued certificate cannot MITM the LDAP connection — the same
///   guarantee the proxy backend paths and `PluginHttpClient` provide.
///
/// - `FERRUM_TLS_CA_BUNDLE_PATH` unset: falls back to webpki bundled roots.
///   This matches the proxy backend paths' webpki fallback (rather than
///   `rustls-platform-verifier`) so behaviour is consistent across all
///   gateway TLS surfaces on Linux containers.
///
/// - `FERRUM_TLS_NO_VERIFY` set: installs the shared [`crate::tls::NoVerifier`]
///   custom certificate verifier (mirroring the proxy backend / WebSocket /
///   gRPC paths) which accepts every cert presented.
///
/// CRL: when `FERRUM_TLS_NO_VERIFY` is not set, the verifier is built via
/// [`crate::tls::build_server_verifier_with_crls()`] with the gateway's parsed
/// CRL list (`crls`, sourced from `PluginHttpClient::tls_crls()`). Revoked LDAP
/// server certificates are rejected, matching the proxy backend / DTLS /
/// frontend mTLS / rustls logging-sink surfaces. An empty `crls` slice yields a
/// plain WebPki verifier (no behavioural change vs. the previous root-store
/// verifier).
pub(crate) fn build_ldap_tls_config(
    no_verify: bool,
    ca_bundle_path: Option<&str>,
    crls: &[CertificateRevocationListDer<'static>],
    live_source: Option<&PluginHttpClient>,
) -> Result<Arc<ClientConfig>, String> {
    // ldap3's `tls-rustls-ring` feature forwards `rustls/ring`, which selects
    // the ring crypto provider for TLS primitives but DOES NOT install it as
    // the rustls global default. Anywhere we hand a `ClientConfig` to ldap3
    // we therefore have to construct it via `with_provider(ring)` so the
    // builder doesn't fall back to the (uninstalled) global default and
    // panic at first use. The gateway's own startup installs ring at
    // `main.rs::install_default()`, but that only matters for code paths
    // that go through the global accessor — `ClientConfig::builder()`
    // without `with_provider()` would also work in production but breaks
    // unit tests that exercise `LdapAuth::new()` before `install_default()`
    // has run. Always supplying the provider explicitly avoids that ordering
    // hazard.
    let provider = Arc::new(crate::fips::base_crypto_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("ldap_auth: failed to build rustls client config: {e}"))?;

    // An explicit CA remains a configuration requirement when verification is
    // disabled. Materialize it before branching so no-verify cannot hide a
    // malformed, empty, or unusable custom trust store.
    let custom_root_store = ca_bundle_path
        .map(|ca_path| build_ldap_root_store(Some(ca_path)))
        .transpose()?;

    let config = if no_verify {
        warn!("ldap_auth: TLS certificate verification DISABLED (FERRUM_TLS_NO_VERIFY=true)");
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier))
            .with_no_client_auth()
    } else {
        // Build a WebPki verifier from the (CA-exclusive) trust store and apply
        // the gateway's parsed CRL list so revoked LDAP server certificates are
        // rejected, matching the proxy backend / DTLS / frontend mTLS / rustls
        // logging-sink surfaces (finding #84). When no CRL is configured this is
        // equivalent to the default root-store verifier. The shared
        // `tls::crl_policy` applied inside `build_server_verifier_with_crls`
        // retains unknown-status tolerance, so certs from CAs without a matching
        // CRL are still accepted.
        let root_store = custom_root_store.unwrap_or_else(|| {
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
        });
        // With a live source the verifier follows CRL generations after a
        // backend TLS reload (#6651) instead of freezing the snapshot list.
        match live_source {
            Some(client) => {
                let verifier = client
                    .crl_server_verifier(root_store)
                    .map_err(|_| "ldap_auth: failed to build TLS verifier".to_string())?;
                let mut config = builder
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth();
                if client.enforces_gateway_crls() {
                    config.resumption = rustls::client::Resumption::disabled();
                }
                config
            }
            None => {
                let verifier = crate::tls::build_server_verifier_with_crls(root_store, crls)
                    .map_err(|_| "ldap_auth: failed to build TLS verifier".to_string())?;
                let mut config = builder.with_webpki_verifier(verifier).with_no_client_auth();
                // The config is reused across LDAP reconnects; resumption would skip
                // the CRL expiration check on a resumed handshake.
                crate::tls::apply_crl_enforced_client_resumption(&mut config, crls);
                config
            }
        }
    };

    Ok(Arc::new(config))
}

/// Build the LDAP TLS trust store, enforcing CA exclusivity when a custom CA
/// is configured. Returns `RootCertStore::empty()` + the bundle's certs when
/// a path is supplied; otherwise webpki bundled roots.
fn build_ldap_root_store(ca_bundle_path: Option<&str>) -> Result<rustls::RootCertStore, String> {
    let Some(ca_path) = ca_bundle_path else {
        // No custom CA — fall back to webpki bundled roots, matching the
        // proxy backend path. We deliberately do NOT mix in OS roots: the
        // gateway runs server-side, the LDAP server is internal, and the
        // operator opted into "ferrum's TLS stack".
        return Ok(rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ));
    };

    let source = CertSource::parse(ca_path, MaterialKind::CaBundle);
    let ca_material = load_material_blocking(&source, MaterialKind::CaBundle).map_err(|_| {
        "ldap_auth: `FERRUM_TLS_CA_BUNDLE_PATH`: failed to load CA bundle".to_string()
    })?;
    let source_id = ca_material.display_source_id.clone();
    let root_store = crate::tls::root_cert_store_from_pem_bundle(
        ca_material.bytes.expose_secret(),
        "ldap_auth CA bundle",
        &source_id,
    )
    .map_err(|_| {
        "ldap_auth: `FERRUM_TLS_CA_BUNDLE_PATH`: CA bundle failed trust-store admission".to_string()
    })?;

    debug!(
        "ldap_auth: loaded {} CA certificate(s) from {} (CA exclusivity enforced)",
        root_store.len(),
        crate::startup::sanitize_startup_scalar(&source_id)
    );
    Ok(root_store)
}

/// Escape a string for use in an LDAP DN value (RFC 4514 §2.4).
///
/// Characters that have special meaning in a DN — `,`, `+`, `"`, `\`, `<`, `>`, `;`
/// — are backslash-escaped. Leading/trailing spaces and a leading `#` are also escaped.
/// NUL has no single-character escape and must be hex-escaped as `\00`.
pub fn escape_dn_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    // `input.len()` is a *byte* length but `enumerate()` yields a *character*
    // index. For inputs containing multi-byte UTF-8 characters they disagree
    // and `i == input.len() - 1` never matches the actual last character, so
    // the trailing-space escape silently never fires. Compare against the
    // character count instead.
    let total_chars = input.chars().count();
    for (i, ch) in input.chars().enumerate() {
        let is_last = i + 1 == total_chars;
        if ch == '\0' {
            out.push_str("\\00");
            continue;
        }
        let needs_escape = matches!(ch, ',' | '+' | '"' | '\\' | '<' | '>' | ';')
            || (i == 0 && (ch == ' ' || ch == '#'))
            || (is_last && ch == ' ');
        if needs_escape {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Substitutes used to syntax-check a configured filter template at admission.
///
/// Both are ordinary RFC 4515 assertion values built from characters that need
/// no escaping, so a template that parses with them substituted also parses
/// with the escaped runtime value in their place.
const LDAP_FILTER_VALIDATION_USERNAME: &str = "ferrumfiltervalidation";
const LDAP_FILTER_VALIDATION_USER_DN: &str = "cn=ferrumfiltervalidation,ou=users,dc=example,dc=com";

/// Reject a configured filter template that is not a well-formed RFC 4515
/// search filter.
///
/// `ldap_auth` fails closed, so a malformed filter such as `(uid={username}`
/// would otherwise pass `validate`, the admin API, and startup, and then turn
/// every request on the route into a `500` once the directory rejects the
/// filter. `ldap3::parse_filter` is the same grammar `ldap3` applies to the
/// filter this plugin sends, so admitting here means the wire filter is
/// well-formed.
fn validate_ldap_filter_syntax(filter: &str, field: &str) -> Result<(), String> {
    let resolved = filter
        .replace("{username}", LDAP_FILTER_VALIDATION_USERNAME)
        .replace("{user_dn}", LDAP_FILTER_VALIDATION_USER_DN);
    if parse_filter(&resolved).is_err() {
        return Err(format!(
            "ldap_auth: `{field}` is not a valid RFC 4515 LDAP search filter"
        ));
    }
    Ok(())
}

/// `member_of` mode: the subtree filter selecting `required_groups` by their
/// `group_attribute` value. The attribute is a validated descriptor and every
/// name is RFC 4515-escaped.
fn required_group_name_filter(group_attribute: &str, required_groups: &[String]) -> String {
    let mut filter = String::from("(|");
    for group in required_groups {
        filter.push('(');
        filter.push_str(group_attribute);
        filter.push('=');
        filter.push_str(&escape_filter_value(group));
        filter.push(')');
    }
    filter.push(')');
    filter
}

/// Maximum `member_of` proof attempts per authentication request, shared by
/// all endpoints, cached re-checks, and uncached fallback. Additional
/// same-named candidates fail closed when no proof slots remain.
const LDAP_AUTH_MAX_MEMBER_OF_PROOFS: usize = 16;

/// Keyed digest over a domain tag, a length-framed username, and optionally
/// the password.
///
/// Credential caches key on the EXACT presented username: whether two
/// spellings name one directory principal depends on the login attribute's
/// matching rule (RFC 4517 `caseExactMatch` exists), so folding them would
/// let one principal's cached result authenticate another.
fn credential_digest(
    key: &[u8; 32],
    domain: u8,
    username: &str,
    password: Option<&str>,
) -> Option<CacheKey> {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        warn!("ldap_auth: failed to initialize cache HMAC");
        return None;
    };
    let username_len = u64::try_from(username.len()).ok()?;
    mac.update([domain]);
    mac.update(username_len.to_be_bytes());
    mac.update(username.as_bytes());
    if let Some(password) = password {
        mac.update(password.as_bytes());
    }
    let digest = mac.finalize().into_bytes();
    let mut cache_key = [0u8; 32];
    cache_key.copy_from_slice(&digest);
    Some(CacheKey(cache_key))
}

/// Prepare a value the way LDAP `caseIgnoreMatch` compares it (RFC 4518
/// insignificant-space handling, then case folding): surrounding whitespace
/// is dropped, interior whitespace runs collapse to one space, and the result
/// is lowercased. Group names and the per-username failure-count key are
/// compared in this form, so `"Domain  Admins "` matches `"domain admins"`
/// exactly as the directory itself would match them.
fn prepare_case_ignore(value: &str) -> String {
    let mut prepared = String::with_capacity(value.len());
    for word in value.split_whitespace() {
        if !prepared.is_empty() {
            prepared.push(' ');
        }
        prepared.push_str(word);
    }
    prepared.to_lowercase()
}

/// RFC 4512 `oid`: a `descr` (`ALPHA *( ALPHA / DIGIT / "-" )`) or a
/// `numericoid` (two or more dot-separated numbers without leading zeros).
fn is_attribute_type(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {
            chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        }
        Some(first) if first.is_ascii_digit() => {
            let mut components = 0usize;
            for number in value.split('.') {
                components += 1;
                if number.is_empty()
                    || !number.bytes().all(|byte| byte.is_ascii_digit())
                    || (number.len() > 1 && number.starts_with('0'))
                {
                    return false;
                }
            }
            components >= 2
        }
        _ => false,
    }
}

/// Reject a configured attribute that is not an RFC 4512 attribute
/// description (`oid *( ";" option )`). Also rejects `1.1`, the special
/// "no attributes" selector, which would make the directory return nothing.
fn validate_attribute_description(value: &str, field: &str) -> Result<(), String> {
    let mut parts = value.split(';');
    let valid = parts.next().is_some_and(is_attribute_type)
        && parts.all(|option| {
            !option.is_empty()
                && option
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        });
    if !valid || value == "1.1" {
        return Err(format!(
            "ldap_auth: `{field}` must be an LDAP attribute description (a name such as `uid`, or a numeric OID, optionally followed by `;option` suffixes)"
        ));
    }
    Ok(())
}

/// Whether `dn` is an RFC 4514 distinguished name.
///
/// Every RDN component must be `type=value` with an attribute-type `oid`; a
/// value is either a `#` hex string or text whose RFC 4514 special characters
/// are escaped. An unescaped `=` inside a value is refused too: RFC 4514
/// permits it, but in a configured DN it almost always marks a missing comma
/// (`ou=users dc=example,dc=com`). Spaces around `,` / `+` / `=` are
/// tolerated, as directories accept them. RFC 2253 `;` separators are
/// accepted, matching the response-side RDN parser.
fn is_distinguished_name(dn: &str) -> bool {
    let mut components = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in dn.chars() {
        if escaped {
            current.push('\\');
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            ',' | ';' | '+' => components.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    if escaped {
        return false;
    }
    components.push(current);
    components
        .iter()
        .all(|component| is_dn_attribute_value_assertion(component.as_str()))
}

fn is_dn_attribute_value_assertion(component: &str) -> bool {
    let mut escaped = false;
    let mut separator = None;
    for (index, ch) in component.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '=' => {
                separator = Some(index);
                break;
            }
            _ => {}
        }
    }
    let Some(separator) = separator else {
        return false;
    };
    if !is_attribute_type(component[..separator].trim()) {
        return false;
    }
    let raw_value = &component[separator + 1..];
    if let Some(hex) = raw_value.trim_start().strip_prefix('#') {
        let hex = hex.trim_end();
        return !hex.is_empty()
            && hex.len() % 2 == 0
            && hex.bytes().all(|byte| byte.is_ascii_hexdigit());
    }
    let mut escaped = false;
    for ch in raw_value.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' | '<' | '>' | '=' | '\0' => return false,
            _ => {}
        }
    }
    unescape_rdn_value(raw_value).is_some()
}

/// Reject a configured base DN that is not an RFC 4514 distinguished name.
fn validate_distinguished_name(dn: &str, field: &str) -> Result<(), String> {
    if is_distinguished_name(dn) {
        Ok(())
    } else {
        Err(format!(
            "ldap_auth: `{field}` is not a valid RFC 4514 distinguished name"
        ))
    }
}

/// Validate a simple-bind name (`bind_dn_template` with its placeholder
/// substituted, or `service_account_dn`).
///
/// Active Directory also accepts a userPrincipalName (`{username}@corp.example.com`)
/// or a down-level logon name (`CORP\{username}`) as the simple-bind name, so
/// only a DN-shaped value (one containing `=`) is held to RFC 4514.
fn validate_bind_name(name: &str, field: &str) -> Result<(), String> {
    if name.contains('=') {
        validate_distinguished_name(name, field)
    } else {
        Ok(())
    }
}

/// Escape a string for use in an LDAP search filter value (RFC 4515 §3).
///
/// The five characters `*`, `(`, `)`, `\`, and NUL are hex-escaped as `\xx`.
/// All other characters — including multi-byte UTF-8 — are passed through
/// unchanged. Iterate over `char`s (not bytes): a byte loop with `byte as char`
/// would re-encode each UTF-8 continuation byte as its own code point,
/// corrupting non-ASCII values so the directory search never matches the entry.
/// The five escaped characters are all single-byte ASCII, so injection
/// protection is unaffected.
pub fn escape_filter_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            _ => out.push(ch),
        }
    }
    out
}

/// RFC 4514 `special` characters plus `ESC` itself: the set a lone backslash
/// may escape without a following hex pair.
const DN_ESCAPABLE_SPECIALS: [char; 10] = ['\\', '"', '+', ',', ';', '<', '>', ' ', '#', '='];

/// One attribute type / value pair of a relative distinguished name.
struct RdnAttributeValue {
    attribute_type: String,
    value: String,
}

/// Parse the leading relative distinguished name of `dn` per RFC 4514.
///
/// Returns every attribute/value pair of the FIRST RDN only (a multi-valued
/// RDN such as `cn=admins+ou=eng` yields two), honoring `\`-escaped separators
/// and `\XX` hex escapes so a value containing a comma or plus cannot be split
/// into a different DN shape. Returns `None` — never a partial guess — for any
/// DN this parser cannot represent as text, including the RFC 4514 `#`
/// hex-encoded BER value form, so callers fail closed.
fn parse_first_rdn(dn: &str) -> Option<Vec<RdnAttributeValue>> {
    let mut pairs = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in dn.chars() {
        if escaped {
            current.push('\\');
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            // RFC 4514 separates RDNs with ','; RFC 2253 also allowed ';'.
            // Either one ends the entry's own RDN.
            ',' | ';' => break,
            '+' => pairs.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    if escaped {
        // Trailing lone escape: the DN is malformed.
        return None;
    }
    pairs.push(current);

    let mut parsed = Vec::with_capacity(pairs.len());
    for pair in pairs {
        parsed.push(parse_rdn_pair(&pair)?);
    }
    Some(parsed)
}

/// Split one `type=value` pair of an RDN at its first unescaped `=`.
fn parse_rdn_pair(pair: &str) -> Option<RdnAttributeValue> {
    let mut escaped = false;
    let mut separator = None;
    for (index, ch) in pair.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '=' => {
                separator = Some(index);
                break;
            }
            _ => {}
        }
    }
    let separator = separator?;
    let attribute_type = pair[..separator].trim();
    if attribute_type.is_empty() {
        return None;
    }
    Some(RdnAttributeValue {
        attribute_type: attribute_type.to_string(),
        value: unescape_rdn_value(&pair[separator + 1..])?,
    })
}

/// Decode the RFC 4514 escaping of an RDN attribute value.
///
/// Unescaped leading and trailing spaces are layout, not value; escaped ones
/// (`\ ` or `\20`) belong to the value and are preserved.
fn unescape_rdn_value(raw: &str) -> Option<String> {
    if raw.trim_start().starts_with('#') {
        // Hex-encoded BER value: not comparable as text.
        return None;
    }
    // Each decoded byte is tagged with whether an escape produced it, so
    // trimming cannot drop a deliberately escaped space.
    let mut decoded: Vec<(u8, bool)> = Vec::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            let mut buffer = [0u8; 4];
            for byte in ch.encode_utf8(&mut buffer).bytes() {
                decoded.push((byte, false));
            }
            continue;
        }
        // RFC 4514 `pair = ESC ( ESC / special / hexpair )`. No `special` is a
        // hex digit, so a hex digit here always begins a hex pair.
        let escaped = chars.next()?;
        match escaped.to_digit(16) {
            Some(high) => {
                let low = chars.next()?.to_digit(16)?;
                decoded.push((u8::try_from(high * 16 + low).ok()?, true));
            }
            None => {
                if !DN_ESCAPABLE_SPECIALS.contains(&escaped) {
                    return None;
                }
                decoded.push((u8::try_from(escaped).ok()?, true));
            }
        }
    }

    let mut start = 0;
    while start < decoded.len() && decoded[start] == (b' ', false) {
        start += 1;
    }
    let mut end = decoded.len();
    while end > start && decoded[end - 1] == (b' ', false) {
        end -= 1;
    }
    let mut bytes = Vec::with_capacity(end - start);
    for (byte, _) in &decoded[start..end] {
        bytes.push(*byte);
    }
    String::from_utf8(bytes).ok()
}

#[async_trait]
impl AuthMechanism for LdapAuth {
    fn mechanism_name(&self) -> &'static str {
        "ldap_auth"
    }

    fn identity_realm_authority(&self) -> Option<[u8; 32]> {
        Some(self.identity_realm_authority)
    }

    /// `ldap_auth` consumes RFC 7617 `Authorization: Basic` credentials, so an
    /// unauthenticated request must be answered with the `Basic` challenge
    /// (RFC 9110 section 11.6.1) — clients that drive Basic authentication off
    /// the challenge never prompt for credentials otherwise. Same value as
    /// `basic_auth`.
    fn authentication_challenge(&self) -> &'static str {
        LDAP_AUTH_BASIC_CHALLENGE
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        // Same contract as `basic_auth`: Basic credentials are base64 (visible
        // ASCII). A present but non-materialized `Authorization` line is invalid,
        // not missing.
        let auth_header = match lookup_configured_header(ctx, "authorization", None) {
            ConfiguredHeaderLookup::Absent => return ExtractedCredential::Missing,
            ConfiguredHeaderLookup::PresentNonMaterialized => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid Authorization header"}"#.into(),
                );
            }
            ConfiguredHeaderLookup::Value(header) => header,
        };

        let encoded = match strip_auth_scheme(&auth_header, "Basic") {
            Some(encoded) => encoded,
            None => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid Basic auth format"}"#.into(),
                );
            }
        };

        let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(decoded) => decoded,
            Err(_) => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid base64 in Basic auth"}"#.into(),
                );
            }
        };

        let credential_str = match String::from_utf8(decoded) {
            Ok(credentials) => credentials,
            Err(_) => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid UTF-8 in Basic auth"}"#.into(),
                );
            }
        };

        let Some((username, password)) = credential_str.split_once(':') else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Invalid Basic auth format"}"#.into(),
            );
        };

        if username.is_empty() {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Username must not be empty"}"#.into(),
            );
        }

        if password.is_empty() {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Password must not be empty"}"#.into(),
            );
        }

        ExtractedCredential::BasicAuth {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let ExtractedCredential::BasicAuth { username, password } = credential else {
            return VerifyOutcome::NotApplicable;
        };
        let password = Zeroizing::new(password);
        // One wall-clock budget for the whole authentication: a group re-check
        // and any uncached fallback after it share it.
        let deadline = tokio::time::Instant::now() + self.request_timeout;
        // One reverse-membership proof budget across every endpoint and any
        // uncached fallback after a stale cached group re-check.
        let mut member_of_proofs_remaining = LDAP_AUTH_MAX_MEMBER_OF_PROOFS;

        // Check cache first
        if let Some(cached) = self.check_cache(&username, &password) {
            debug!("ldap_auth: cache hit for user '{}'", username);
            if !cached.groups_due {
                return self.identity_outcome(&cached.canonical_identity, consumer_index);
            }
            match self
                .revalidate_cached_groups(
                    &username,
                    &password,
                    cached,
                    consumer_index,
                    deadline,
                    &mut member_of_proofs_remaining,
                )
                .await
            {
                CachedGroupRevalidation::Decided(outcome) => return outcome,
                // The entry lapsed or was replaced during the check: fall
                // through to a full uncached authentication.
                CachedGroupRevalidation::Stale => {}
            }
        }

        // Refuse a credential the directory just rejected, or a username in a
        // failed-attempt backoff, without spending a directory flow on it. Both
        // are opt-in; the response matches an ordinary rejection.
        if self.credential_recently_rejected(&username, &password) {
            debug!("ldap_auth: credential refused without a directory round trip");
            return VerifyOutcome::Invalid(r#"{"error":"LDAP authentication failed"}"#.into());
        }
        match self.account_admission(&username) {
            AccountAdmission::Allowed => {}
            AccountAdmission::Blocked => {
                debug!("ldap_auth: username refused inside its failed-attempt backoff");
                return VerifyOutcome::Invalid(r#"{"error":"LDAP authentication failed"}"#.into());
            }
            AccountAdmission::Saturated => {
                warn!(
                    "ldap_auth: per-username failure tracker is full of live state; refusing an untracked username"
                );
                return VerifyOutcome::Internal(
                    r#"{"error":"LDAP authentication temporarily unavailable"}"#.into(),
                );
            }
        }

        let _permit = match self.ldap_concurrency.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                warn!("ldap_auth: maximum concurrent authentication work reached");
                return VerifyOutcome::Internal(
                    r#"{"error":"LDAP authentication temporarily unavailable"}"#.into(),
                );
            }
        };

        match tokio::time::timeout_at(
            deadline,
            self.verify_uncached(
                &username,
                &password,
                consumer_index,
                &mut member_of_proofs_remaining,
            ),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => {
                warn!("ldap_auth: authentication exceeded the configured wall-clock deadline");
                VerifyOutcome::Internal(
                    r#"{"error":"LDAP authentication temporarily unavailable"}"#.into(),
                )
            }
        }
    }
}

auth_flow::impl_auth_plugin!(
    LdapAuth,
    "ldap_auth",
    super::priority::LDAP_AUTH,
    crate::plugins::HTTP_FAMILY_PROTOCOLS,
    auth_flow::run_auth_external_identity;
    fn warmup_hostnames(&self) -> Vec<String> {
        self.endpoints
            .iter()
            .map(|endpoint| endpoint.hostname.clone())
            .collect()
    }

    fn request_headers_to_redact(&self) -> &[String] {
        &self.request_headers_to_redact
    }

    fn modifies_request_headers(&self) -> bool {
        self.hide_credentials
    }

    /// `hide_credentials` removes only the Basic `Authorization` field.
    fn modified_request_header_names(&self) -> Option<Vec<String>> {
        Some(vec!["authorization".to_string()])
    }

    async fn before_proxy(
        &self,
        _ctx: &mut crate::plugins::RequestContext,
        headers: &mut std::collections::HashMap<String, String>,
    ) -> crate::plugins::PluginResult {
        if self.hide_credentials {
            // Removal is unconditional at this point, so a chain where another
            // mechanism authenticated the request still cannot leak the Basic
            // password upstream. Only the `Basic` scheme this plugin consumes
            // is removed: an `Authorization` header carrying another scheme
            // belongs to a different policy and must reach the backend intact.
            headers.retain(|name, value| {
                let is_basic_credential = name.eq_ignore_ascii_case("authorization")
                    && crate::plugins::strip_auth_scheme(value, "Basic").is_some();
                !is_basic_credential
            });
        }
        crate::plugins::PluginResult::Continue
    }
);

impl LdapAuth {
    /// Re-run the `required_groups` search for a cache hit whose last group
    /// check is older than `group_cache_ttl`, under the same concurrency and
    /// wall-clock bounds as an uncached authentication (the request's single
    /// `deadline`), further capped by the observed entry's remaining lifetime.
    ///
    /// A user no longer in any required group is refused (403) and the
    /// observed entry is evicted. A directory failure or deadline fails closed
    /// (500) and keeps the entry, so the next hit retries the check. Success
    /// admits only while the very entry that was checked is still live;
    /// otherwise the caller falls back to an uncached authentication, so a
    /// slow check can never stretch a credential past `cache_ttl_seconds`.
    async fn revalidate_cached_groups(
        &self,
        username: &str,
        password: &str,
        cached: CachedAuthentication,
        consumer_index: &ConsumerIndex,
        deadline: tokio::time::Instant,
        member_of_proofs_remaining: &mut usize,
    ) -> CachedGroupRevalidation {
        let remaining = cached.expires_at.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return CachedGroupRevalidation::Stale;
        }
        let budget = deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .min(remaining);
        let _permit = match self.ldap_concurrency.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                warn!("ldap_auth: maximum concurrent authentication work reached");
                return CachedGroupRevalidation::Decided(VerifyOutcome::Internal(
                    r#"{"error":"LDAP authentication temporarily unavailable"}"#.into(),
                ));
            }
        };
        let membership = tokio::time::timeout(
            budget,
            self.check_group_membership_with_failover(
                &cached.user_dn,
                &cached.canonical_identity,
                member_of_proofs_remaining,
            ),
        )
        .await;
        let outcome = match membership {
            Ok(Ok(true)) => {
                if !self.mark_cached_groups_verified(username, password, cached.generation) {
                    return CachedGroupRevalidation::Stale;
                }
                self.identity_outcome(&cached.canonical_identity, consumer_index)
            }
            Ok(Ok(false)) => {
                self.evict_cached_authentication(username, password, cached.generation);
                warn!(
                    "ldap_auth: cached user '{}' is no longer a member of any required group",
                    cached.canonical_identity
                );
                VerifyOutcome::Forbidden(
                    r#"{"error":"User is not a member of any required group"}"#.into(),
                )
            }
            Ok(Err(e)) => {
                warn!("{}", e.log_message());
                VerifyOutcome::Internal(r#"{"error":"LDAP group membership check failed"}"#.into())
            }
            Err(_) if Instant::now() >= cached.expires_at => {
                return CachedGroupRevalidation::Stale;
            }
            Err(_) => {
                warn!("ldap_auth: group re-check exceeded the configured wall-clock deadline");
                VerifyOutcome::Internal(
                    r#"{"error":"LDAP authentication temporarily unavailable"}"#.into(),
                )
            }
        };
        CachedGroupRevalidation::Decided(outcome)
    }

    async fn verify_uncached(
        &self,
        presented_username: &str,
        password: &str,
        consumer_index: &ConsumerIndex,
        member_of_proofs_remaining: &mut usize,
    ) -> VerifyOutcome {
        // Authenticate against LDAP. Distinguish a genuine credential failure
        // (401) from a backend/config failure (500); see finding #32. The
        // client always receives a generic message — the specific cause is only
        // logged via `warn!`.
        let authenticated_user = match self
            .authenticate_user_with_failover(presented_username, password)
            .await
        {
            Ok(user) => user,
            Err(AuthError::Credential(e)) => {
                warn!("{}", e);
                self.record_credential_failure(presented_username, password);
                return VerifyOutcome::Invalid(r#"{"error":"LDAP authentication failed"}"#.into());
            }
            Err(AuthError::Backend(e) | AuthError::Unavailable(e)) => {
                warn!("{}", e);
                return VerifyOutcome::Internal(
                    r#"{"error":"LDAP authentication temporarily unavailable"}"#.into(),
                );
            }
        };
        // The password was accepted, so any failure run for this username ends
        // here, whatever the group check decides.
        self.clear_account_failures(presented_username);

        if !self.required_groups.is_empty() {
            match self
                .check_group_membership_with_failover(
                    &authenticated_user.dn,
                    &authenticated_user.canonical_identity,
                    member_of_proofs_remaining,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    warn!(
                        "ldap_auth: user '{}' is not a member of any required group",
                        authenticated_user.canonical_identity
                    );
                    return VerifyOutcome::Forbidden(
                        r#"{"error":"User is not a member of any required group"}"#.into(),
                    );
                }
                Err(e) => {
                    warn!("{}", e.log_message());
                    return VerifyOutcome::Internal(
                        r#"{"error":"LDAP group membership check failed"}"#.into(),
                    );
                }
            }
        }

        self.set_cache(presented_username, password, &authenticated_user);

        debug!(
            "ldap_auth: authenticated canonical identity '{}'",
            authenticated_user.canonical_identity
        );
        self.identity_outcome(&authenticated_user.canonical_identity, consumer_index)
    }

    /// Build the auth result for a successfully authenticated LDAP user.
    fn identity_outcome(&self, username: &str, _consumer_index: &ConsumerIndex) -> VerifyOutcome {
        // A directory username is not a Consumer credential binding. Until
        // mappings can name the directory authority explicitly, keep the
        // verified principal external.
        VerifyOutcome::success(None, Some(username.to_string()), Some(username.to_string()))
    }
}

#[cfg(test)]
mod tests {
    //! Inline tests for private TLS-config helpers. Lives here per CLAUDE.md
    //! "Test Placement": private fns are tested via inline `#[cfg(test)]`
    //! modules — they cannot be promoted to `pub` solely for external testing.

    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    use rustls::pki_types::ServerName;
    use rustls::pki_types::pem::PemObject;
    use std::io::Write;
    use std::sync::Once;
    use tempfile::NamedTempFile;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    static INIT_CRYPTO: Once = Once::new();

    fn ensure_crypto_provider() {
        INIT_CRYPTO.call_once(|| {
            let _ = crate::fips::base_crypto_provider().install_default();
        });
    }

    fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }

    fn must_some<T>(value: Option<T>, context: &str) -> T {
        match value {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }

    fn test_user(name: &str) -> AuthenticatedUser {
        AuthenticatedUser {
            dn: format!("uid={name},dc=example,dc=com"),
            canonical_identity: name.to_string(),
        }
    }

    fn cached_group_test_plugin(group_cache_ttl_seconds: u64) -> LdapAuth {
        must(
            LdapAuth::new(
                &serde_json::json!({
                    "ldap_url": "ldap://127.0.0.1:389",
                    "bind_dn_template": "uid={username},dc=example,dc=com",
                    "canonical_identity_attribute": "uid",
                    "group_base_dn": "ou=groups,dc=example,dc=com",
                    "required_groups": ["admins"],
                    "cache_ttl_seconds": 60,
                    "group_cache_ttl_seconds": group_cache_ttl_seconds
                }),
                PluginHttpClient::default(),
            ),
            "build cached LDAP group plugin",
        )
    }

    #[test]
    fn cache_hit_reports_group_recheck_due_only_after_group_ttl() {
        let fresh = cached_group_test_plugin(60);
        fresh.set_cache("alice", "password", &test_user("alice"));
        let hit = must_some(fresh.check_cache("alice", "password"), "fresh cache hit");
        assert!(
            !hit.groups_due,
            "a just-verified entry needs no group re-check"
        );
        assert_eq!(hit.user_dn, "uid=alice,dc=example,dc=com");

        let every_hit = cached_group_test_plugin(0);
        every_hit.set_cache("alice", "password", &test_user("alice"));
        let hit = must_some(every_hit.check_cache("alice", "password"), "cache hit");
        assert!(
            hit.groups_due,
            "group_cache_ttl_seconds = 0 re-checks every hit"
        );

        // Recording a successful re-check is bounded by the entry's own expiry
        // and the group TTL.
        let mut refreshed = cached_group_test_plugin(0);
        refreshed.set_cache("alice", "password", &test_user("alice"));
        refreshed.group_cache_ttl = Duration::from_secs(30);
        let observed = must_some(refreshed.check_cache("alice", "password"), "cache hit");
        assert!(refreshed.mark_cached_groups_verified("alice", "password", observed.generation));
        let hit = must_some(refreshed.check_cache("alice", "password"), "cache hit");
        assert!(!hit.groups_due);

        refreshed.evict_cached_authentication("alice", "password", observed.generation);
        assert!(refreshed.check_cache("alice", "password").is_none());
        assert_eq!(refreshed.cache_entries.load(Ordering::Acquire), 0);
    }

    /// A re-check that raced a replacement under the same key neither
    /// refreshes nor evicts the replacement, and does not admit.
    #[test]
    fn group_recheck_is_bound_to_the_entry_it_observed() {
        let plugin = cached_group_test_plugin(0);
        plugin.set_cache("alice", "password", &test_user("alice"));
        let observed = must_some(plugin.check_cache("alice", "password"), "cache hit");
        // A concurrent uncached authentication replaces the entry.
        plugin.set_cache("alice", "password", &test_user("alice"));
        let replacement = must_some(plugin.check_cache("alice", "password"), "cache hit");
        assert_ne!(observed.generation, replacement.generation);

        assert!(
            !plugin.mark_cached_groups_verified("alice", "password", observed.generation),
            "a stale re-check must not admit through the replacement"
        );
        plugin.evict_cached_authentication("alice", "password", observed.generation);
        let survivor = must_some(plugin.check_cache("alice", "password"), "replacement kept");
        assert_eq!(survivor.generation, replacement.generation);
        assert_eq!(plugin.cache_entries.load(Ordering::Acquire), 1);
    }

    /// An entry that expired while its re-check ran is not admitted.
    #[test]
    fn group_recheck_does_not_admit_an_expired_entry() {
        let plugin = cached_group_test_plugin(0);
        plugin.set_cache("alice", "password", &test_user("alice"));
        let observed = must_some(plugin.check_cache("alice", "password"), "cache hit");
        let key = must_some(plugin.cache_key("alice", "password"), "cache key");
        if let Some(mut entry) = plugin.cache.get_mut(&key) {
            entry.expires_at = Instant::now();
        }
        assert!(!plugin.mark_cached_groups_verified("alice", "password", observed.generation));
        assert!(plugin.check_cache("alice", "password").is_none());
        assert_eq!(plugin.cache_entries.load(Ordering::Acquire), 0);
    }

    #[test]
    fn cache_hit_without_required_groups_never_rechecks_groups() {
        let plugin = cached_test_plugin(4);
        plugin.set_cache("alice", "password", &test_user("alice"));
        let hit = must_some(plugin.check_cache("alice", "password"), "cache hit");
        assert!(!hit.groups_due);
    }

    fn cached_test_plugin(max_cache_entries: usize) -> LdapAuth {
        must(
            LdapAuth::new(
                &serde_json::json!({
                    "ldap_url": "ldap://127.0.0.1:389",
                    "bind_dn_template": "uid={username},dc=example,dc=com",
                    "canonical_identity_attribute": "uid",
                    "cache_ttl_seconds": 60,
                    "max_cache_entries": max_cache_entries
                }),
                PluginHttpClient::default(),
            ),
            "build cached LDAP plugin",
        )
    }

    #[test]
    fn raised_connect_timeout_raises_the_default_whole_flow_deadline() {
        let plugin = must(
            LdapAuth::new(
                &serde_json::json!({
                    "ldap_url": "ldap://127.0.0.1:389",
                    "bind_dn_template": "uid={username},dc=example,dc=com",
                    "canonical_identity_attribute": "uid",
                    "connect_timeout_seconds": 60
                }),
                PluginHttpClient::default(),
            ),
            "build LDAP plugin with raised operation timeout",
        );

        assert_eq!(plugin.request_timeout, Duration::from_secs(60));
    }

    #[test]
    fn group_username_placeholder_uses_the_authenticated_canonical_identity() {
        let plugin = must(
            LdapAuth::new(
                &serde_json::json!({
                    "ldap_url": "ldap://127.0.0.1:389",
                    "search_base_dn": "ou=users,dc=example,dc=com",
                    "search_filter": "(mail={username})",
                    "canonical_identity_attribute": "entryUUID",
                    "service_account_dn": "cn=admin,dc=example,dc=com",
                    "service_account_password": "service-secret",
                    "group_base_dn": "ou=groups,dc=example,dc=com",
                    "group_filter": "(memberUid={username})",
                    "required_groups": ["admins"]
                }),
                PluginHttpClient::default(),
            ),
            "build search-bind LDAP plugin",
        );

        assert_eq!(
            plugin.group_search_filter(
                "entryUUID=immutable-id,ou=users,dc=example,dc=com",
                "immutable-id",
            ),
            "(memberUid=immutable-id)"
        );
    }

    #[test]
    fn cache_key_is_random_keyed_hmac_not_bare_password_digest() {
        let first = cached_test_plugin(4);
        let second = cached_test_plugin(4);
        let first_key = must_some(first.cache_key("alice", "password"), "first cache key");
        let second_key = must_some(second.cache_key("alice", "password"), "second cache key");
        let bare_password_digest = crate::fips::approved::Sha256::digest(b"password");

        assert_ne!(first_key.0, bare_password_digest);
        assert_ne!(first_key.0, second_key.0);
    }

    #[test]
    fn saturated_cache_replaces_one_entry_and_preserves_hard_cap() {
        let plugin = cached_test_plugin(4);
        for index in 0..100 {
            let username = format!("user-{index}");
            plugin.set_cache(&username, "password", &test_user(&username));
            assert!(plugin.cache.len() <= 4);
            assert!(plugin.cache_entries.load(Ordering::Acquire) <= 4);
        }

        assert_eq!(plugin.cache.len(), 4);
        assert_eq!(plugin.cache_entries.load(Ordering::Acquire), 4);
        assert_eq!(
            plugin
                .check_cache("user-99", "password")
                .map(|cached| cached.canonical_identity)
                .as_deref(),
            Some("user-99")
        );
    }

    #[test]
    fn concurrent_cache_admission_never_exceeds_hard_cap() {
        let plugin = Arc::new(cached_test_plugin(8));
        std::thread::scope(|scope| {
            for worker in 0..32 {
                let plugin = Arc::clone(&plugin);
                scope.spawn(move || {
                    for item in 0..32 {
                        let username = format!("worker-{worker}-item-{item}");
                        plugin.set_cache(&username, "password", &test_user(&username));
                    }
                });
            }
        });

        assert!(plugin.cache.len() <= 8);
        assert_eq!(
            plugin.cache_entries.load(Ordering::Acquire),
            plugin.cache.len()
        );
    }

    #[test]
    fn unrepresentable_cache_expiry_is_skipped_without_panicking() {
        let mut plugin = cached_test_plugin(4);
        plugin.cache_ttl = Duration::MAX;
        plugin.set_cache("alice", "password", &test_user("alice"));
        assert!(plugin.cache.is_empty());
        assert_eq!(plugin.cache_entries.load(Ordering::Acquire), 0);
    }

    #[test]
    fn case_variant_duplicate_ldap_attributes_fail_closed() {
        let attrs = HashMap::from([
            ("sAMAccountName".to_string(), vec!["admins".to_string()]),
            ("samaccountname".to_string(), vec!["guests".to_string()]),
        ]);
        let result = ldap_attribute_values(&attrs, "SAMACCOUNTNAME", "group");
        assert!(result.is_err());
    }

    struct TestCa {
        cert_pem: String,
        issuer: Issuer<'static, KeyPair>,
    }

    fn generate_test_ca(cn: &str) -> TestCa {
        let key_pair = must(
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
            "generate CA key",
        );
        let mut params = must(
            CertificateParams::new(Vec::<String>::new()),
            "build CA params",
        );
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        // `CrlSign` lets this CA also sign CRLs (required by rcgen for the CRL
        // revocation test); harmless for the CA-exclusivity tests.
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        let cert = must(params.self_signed(&key_pair), "self-sign CA");
        TestCa {
            cert_pem: cert.pem(),
            issuer: Issuer::new(params, key_pair),
        }
    }

    /// Generate a leaf certificate (cert PEM + key PEM) signed by `ca` for the
    /// given SANs. Used to stand up a TLS listener in CA-exclusivity tests.
    fn generate_signed_leaf(ca: &TestCa, cn: &str, sans: &[&str]) -> (String, String) {
        let key_pair = must(
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
            "generate leaf key",
        );
        let mut params = must(
            CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            "build leaf params",
        );
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let cert = must(params.signed_by(&key_pair, &ca.issuer), "sign leaf");
        (cert.pem(), key_pair.serialize_pem())
    }

    fn write_pem_to_temp(pem: &str) -> NamedTempFile {
        let mut f = must(NamedTempFile::new(), "create temp CA file");
        must(f.write_all(pem.as_bytes()), "write CA PEM");
        f
    }

    /// Build a rustls server `ServerConfig` from leaf PEM cert + PEM key.
    fn build_server_config(cert_pem: &str, key_pem: &str) -> Arc<rustls::ServerConfig> {
        let certs: Vec<CertificateDer<'static>> = must(
            CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>(),
            "parse leaf cert",
        );
        let key: rustls::pki_types::PrivateKeyDer<'static> = must_some(
            must(
                crate::tls::first_pem_private_key(key_pem.as_bytes()),
                "parse private key",
            ),
            "private key should be present",
        );
        let provider = Arc::new(crate::fips::base_crypto_provider());
        let builder = must(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions(),
            "configure TLS protocol versions",
        );
        let cfg = must(
            builder.with_no_client_auth().with_single_cert(certs, key),
            "build TLS server cert config",
        );
        Arc::new(cfg)
    }

    /// Stand up a one-shot TLS listener on 127.0.0.1, return the bound port +
    /// the listener task handle (which completes after one accepted handshake).
    async fn spawn_oneshot_tls_server(
        server_cfg: Arc<rustls::ServerConfig>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = must(TcpListener::bind("127.0.0.1:0").await, "bind TLS server");
        let port = must(listener.local_addr(), "read TLS server local addr").port();
        let acceptor = TlsAcceptor::from(server_cfg);
        let task = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = acceptor.accept(stream).await; // ignore - test asserts on client side
            }
        });
        (port, task)
    }

    async fn dial_with_config(port: u16, client_cfg: Arc<ClientConfig>) -> std::io::Result<()> {
        let connector = TlsConnector::from(client_cfg);
        let stream = TcpStream::connect(("127.0.0.1", port)).await?;
        let server_name =
            ServerName::try_from("localhost").map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut tls = connector.connect(server_name, stream).await?;
        // Drive the handshake to completion via a tiny round-trip, otherwise some
        // failures only surface on first I/O.
        let _ = tls.write_all(b"x").await;
        let mut buf = [0u8; 1];
        let _ = tls.read(&mut buf).await;
        Ok(())
    }

    #[test]
    fn no_verify_returns_arc_clientconfig() {
        ensure_crypto_provider();
        let cfg = must(
            build_ldap_tls_config(true, None, &[], None),
            "build no-verify config",
        );
        // Cheap structural smoke check: must be an Arc<ClientConfig>.
        let _: &ClientConfig = cfg.as_ref();
    }

    #[test]
    fn missing_ca_bundle_path_falls_back_to_webpki() {
        ensure_crypto_provider();
        let cfg = must(
            build_ldap_tls_config(false, None, &[], None),
            "build webpki config",
        );
        let _: &ClientConfig = cfg.as_ref();
    }

    #[test]
    fn empty_ca_bundle_rejected() {
        ensure_crypto_provider();
        let f = must(NamedTempFile::new(), "create empty temp CA file");
        let err = build_ldap_tls_config(false, f.path().to_str(), &[], None).unwrap_err();
        assert!(
            err.contains("`FERRUM_TLS_CA_BUNDLE_PATH`: CA bundle failed trust-store admission"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn no_verify_still_rejects_empty_declared_ca_bundle() {
        ensure_crypto_provider();
        let f = must(NamedTempFile::new(), "create empty temp CA file");
        let err = build_ldap_tls_config(true, f.path().to_str(), &[], None).unwrap_err();
        assert!(
            err.contains("`FERRUM_TLS_CA_BUNDLE_PATH`: CA bundle failed trust-store admission"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn missing_ca_bundle_file_rejected() {
        ensure_crypto_provider();
        let err =
            build_ldap_tls_config(false, Some("/nonexistent/path/ca.pem"), &[], None).unwrap_err();
        assert!(
            err.contains("`FERRUM_TLS_CA_BUNDLE_PATH`: failed to load CA bundle"),
            "unexpected error: {err}"
        );
        assert!(!err.contains("/nonexistent/path/ca.pem"), "{err}");
    }

    /// Proves CA exclusivity: a config built with CA-A successfully completes a
    /// TLS handshake against a server whose cert is signed by CA-A.
    #[tokio::test(flavor = "current_thread")]
    async fn custom_ca_accepts_matching_cert() {
        ensure_crypto_provider();
        let ca_a = generate_test_ca("Test CA A");
        let (leaf_pem, leaf_key_pem) = generate_signed_leaf(&ca_a, "localhost", &["localhost"]);

        let ca_file = write_pem_to_temp(&ca_a.cert_pem);
        let client_cfg = must(
            build_ldap_tls_config(false, ca_file.path().to_str(), &[], None),
            "build client config",
        );

        let server_cfg = build_server_config(&leaf_pem, &leaf_key_pem);
        let (port, _task) = spawn_oneshot_tls_server(server_cfg).await;

        let result = dial_with_config(port, client_cfg).await;
        assert!(
            result.is_ok(),
            "handshake should succeed against matching CA, got: {result:?}"
        );
    }

    /// Proves CA exclusivity: a config built with CA-A REJECTS a server cert
    /// signed by CA-B. If the system / webpki public roots were leaking into
    /// the trust store (the native-tls regression we're fixing), this test
    /// would still fail — but for the wrong reason — because both CA-A and
    /// CA-B are private and not in any public root program. The point of the
    /// test is the positive direction: when we trust CA-A and the server
    /// uses CA-B, we explicitly fail.
    #[tokio::test(flavor = "current_thread")]
    async fn custom_ca_rejects_mismatched_cert() {
        ensure_crypto_provider();
        let ca_a = generate_test_ca("Test CA A");
        let ca_b = generate_test_ca("Test CA B");
        let (leaf_pem_b, leaf_key_pem_b) = generate_signed_leaf(&ca_b, "localhost", &["localhost"]);

        // Build config trusting only CA-A; server presents CA-B-signed cert.
        let ca_file = write_pem_to_temp(&ca_a.cert_pem);
        let client_cfg = must(
            build_ldap_tls_config(false, ca_file.path().to_str(), &[], None),
            "build client config",
        );

        let server_cfg = build_server_config(&leaf_pem_b, &leaf_key_pem_b);
        let (port, _task) = spawn_oneshot_tls_server(server_cfg).await;

        let result = dial_with_config(port, client_cfg).await;
        assert!(
            result.is_err(),
            "handshake should FAIL when server cert is signed by an untrusted CA"
        );
    }

    /// Proves CA exclusivity at the trust-store layer (no handshake):
    /// `RootCertStore::empty()` + the configured bundle is the ENTIRE trust
    /// store. We verify this by counting roots in the constructed store and
    /// asserting it matches the bundle's cert count exactly — i.e. the
    /// system / webpki roots (~150) were NOT mixed in.
    #[test]
    fn custom_ca_excludes_webpki_roots() {
        ensure_crypto_provider();
        let ca = generate_test_ca("Test CA Exclusive");
        let ca_file = write_pem_to_temp(&ca.cert_pem);
        let store = must(
            build_ldap_root_store(ca_file.path().to_str()),
            "build custom trust store",
        );
        // Single CA in bundle → exactly 1 trust anchor.
        assert_eq!(
            store.len(),
            1,
            "Custom CA must produce a single-anchor trust store; \
             a value > 1 indicates webpki / system roots leaked in"
        );

        // Sanity: the no-CA path falls back to webpki bundled roots, which
        // is many anchors — proves our test setup wasn't trivially passing.
        let webpki_store = must(build_ldap_root_store(None), "build webpki trust store");
        assert!(
            webpki_store.len() > 10,
            "webpki fallback should populate many trust anchors"
        );
    }

    /// Generate a leaf cert (PEM cert + PEM key) signed by `ca` with an explicit
    /// serial number, so a CRL can reference it. Mirrors `generate_signed_leaf`.
    fn generate_signed_leaf_with_serial(
        ca: &TestCa,
        cn: &str,
        sans: &[&str],
        serial: u64,
    ) -> (String, String) {
        let key_pair = must(
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
            "generate leaf key",
        );
        let mut params = must(
            CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            "build leaf params",
        );
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.serial_number = Some(rcgen::SerialNumber::from(serial));
        let cert = must(params.signed_by(&key_pair, &ca.issuer), "sign leaf");
        (cert.pem(), key_pair.serialize_pem())
    }

    /// Build a CRL signed by `ca` revoking the given certificate serial.
    fn build_crl_revoking(ca: &TestCa, serial: u64) -> CertificateRevocationListDer<'static> {
        use rcgen::{
            CertificateRevocationListParams, RevocationReason, RevokedCertParams, SerialNumber,
        };
        use time::{Duration as TimeDuration, OffsetDateTime};

        let now = OffsetDateTime::now_utc();
        let params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + TimeDuration::days(7),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from(serial),
                revocation_time: now,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            }],
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        let crl = must(params.signed_by(&ca.issuer), "sign CRL");
        crl.der().clone()
    }

    /// Finding #84: with a gateway CRL configured, a revoked LDAP server
    /// certificate is REJECTED during the TLS handshake; without the CRL the
    /// same (otherwise valid, CA-trusted) certificate is ACCEPTED. The
    /// before/after contrast proves the CRL — not some other validation step —
    /// is what blocks the revoked cert.
    #[tokio::test(flavor = "current_thread")]
    async fn crl_rejects_revoked_server_cert() {
        ensure_crypto_provider();
        const REVOKED_SERIAL: u64 = 0x5151;

        let ca = generate_test_ca("Test CA CRL");
        let (leaf_pem, leaf_key_pem) =
            generate_signed_leaf_with_serial(&ca, "localhost", &["localhost"], REVOKED_SERIAL);
        let ca_file = write_pem_to_temp(&ca.cert_pem);
        let crl = build_crl_revoking(&ca, REVOKED_SERIAL);

        // Without a CRL: the CA-signed cert is trusted, handshake succeeds.
        let cfg_no_crl = must(
            build_ldap_tls_config(false, ca_file.path().to_str(), &[], None),
            "build no-CRL config",
        );
        let server_cfg = build_server_config(&leaf_pem, &leaf_key_pem);
        let (port, _task) = spawn_oneshot_tls_server(server_cfg).await;
        let ok = dial_with_config(port, cfg_no_crl).await;
        assert!(
            ok.is_ok(),
            "handshake should SUCCEED without a CRL (baseline), got: {ok:?}"
        );

        // With the CRL revoking this serial: handshake must fail.
        let cfg_with_crl = must(
            build_ldap_tls_config(
                false,
                ca_file.path().to_str(),
                std::slice::from_ref(&crl),
                None,
            ),
            "build CRL config",
        );
        let server_cfg = build_server_config(&leaf_pem, &leaf_key_pem);
        let (port, _task) = spawn_oneshot_tls_server(server_cfg).await;
        let revoked = dial_with_config(port, cfg_with_crl).await;
        assert!(
            revoked.is_err(),
            "handshake must FAIL when the server cert is revoked by the CRL"
        );
    }
}
