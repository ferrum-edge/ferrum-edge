use crate::fips::approved::Sha256;
use crossbeam_queue::ArrayQueue;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry as DashEntry;
use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::warn;

pub const DEFAULT_MAX_CACHE_ENTRY_BYTES: usize = 16 * 1024;
pub const MIN_MAX_CACHE_ENTRY_BYTES: usize = 256;
pub const HARD_MAX_CACHE_ENTRY_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_CACHE_TOTAL_BYTES: usize = 16 * 1024 * 1024;
pub const MIN_MAX_CACHE_TOTAL_BYTES: usize = 1024 * 1024;
pub const HARD_MAX_CACHE_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_MAX_CACHE_ENTRIES: usize = 10_000;
pub const MIN_MAX_CACHE_ENTRIES: usize = 100;
pub const HARD_MAX_CACHE_ENTRIES: usize = 100_000;

const NEGATIVE_BUDGET_DIVISOR: usize = 4;
const EVICTION_WORK_LIMIT: usize = 16;
const ARC_ALLOCATION_OVERHEAD: usize = size_of::<AtomicUsize>() * 2;

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct TokenKey {
    digest: [u8; 32],
}

impl TokenKey {
    pub fn from_token(token: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let digest: [u8; 32] = hasher.finalize();
        Self { digest }
    }

    #[cfg(test)]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

pub struct CachedClaimHeader {
    pub mapping_index: usize,
    pub value: Box<str>,
}

pub struct CachedAuthorizationError {
    pub status_code: u16,
    pub body: Box<str>,
}

/// The bounded authorization material needed after an introspection lookup.
///
/// Provider-controlled response members that are not used for authorization,
/// identity selection, or configured header fan-out are deliberately absent.
/// This prevents a valid but arbitrary JSON response from becoming long-lived
/// cache state.
pub struct CachedAuthorization {
    pub authorization_error: Option<CachedAuthorizationError>,
    pub identity: Option<Box<str>>,
    pub identity_header: Option<Box<str>>,
    pub claim_headers: Box<[CachedClaimHeader]>,
}

impl CachedAuthorization {
    pub fn retained_bytes(&self) -> usize {
        let identity_bytes = self.identity.as_deref().map_or(0, str::len);
        let identity_header_bytes = self.identity_header.as_deref().map_or(0, str::len);
        let error_bytes = self
            .authorization_error
            .as_ref()
            .map_or(0, |error| error.body.len());
        let header_bytes = self.claim_headers.iter().fold(0usize, |bytes, header| {
            bytes.saturating_add(header.value.len())
        });
        size_of::<Self>()
            .saturating_add(ARC_ALLOCATION_OVERHEAD)
            .saturating_add(identity_bytes)
            .saturating_add(identity_header_bytes)
            .saturating_add(error_bytes)
            .saturating_add(
                self.claim_headers
                    .len()
                    .saturating_mul(size_of::<CachedClaimHeader>()),
            )
            .saturating_add(header_bytes)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EntryClass {
    Active,
    Negative,
}

impl EntryClass {
    fn index(self) -> usize {
        match self {
            Self::Active => 0,
            Self::Negative => 1,
        }
    }

    fn metric_label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Negative => "negative",
        }
    }
}

enum EntryValue {
    Active(Arc<CachedAuthorization>),
    Negative,
}

struct Entry {
    value: EntryValue,
    expires_at: Instant,
    generation: u64,
    recently_used: AtomicBool,
    _reservation: AdmissionReservation,
}

impl Entry {
    fn class(&self) -> EntryClass {
        match &self.value {
            EntryValue::Active(_) => EntryClass::Active,
            EntryValue::Negative => EntryClass::Negative,
        }
    }
}

pub enum CacheLookup {
    Active(Arc<CachedAuthorization>),
    Negative,
    Miss,
}

#[derive(Clone)]
struct EvictionTicket {
    key: TokenKey,
    generation: u64,
}

struct ClassBudget {
    entries: AtomicUsize,
    retained_bytes: AtomicUsize,
    max_entries: usize,
    max_retained_bytes: usize,
    fixed_index_bytes: usize,
}

impl ClassBudget {
    fn new(max_entries: usize, max_retained_bytes: usize) -> Self {
        Self {
            entries: AtomicUsize::new(0),
            retained_bytes: AtomicUsize::new(0),
            max_entries,
            max_retained_bytes,
            fixed_index_bytes: max_entries.saturating_mul(size_of::<EvictionTicket>()),
        }
    }
}

struct CacheBudget {
    active: ClassBudget,
    negative: ClassBudget,
}

impl CacheBudget {
    fn new(max_entries: usize, max_total_bytes: usize) -> Self {
        let negative_entries = (max_entries / NEGATIVE_BUDGET_DIVISOR).max(1);
        let active_entries = max_entries.saturating_sub(negative_entries).max(1);
        let fixed_index_bytes = max_entries.saturating_mul(size_of::<EvictionTicket>());
        let entry_bytes = max_total_bytes.saturating_sub(fixed_index_bytes);
        // Negative entries own no variable payload, so their byte partition is
        // exactly the minimum fixed entry/key footprint. All remaining bytes
        // belong to active normalized results. This guarantees that a result
        // exactly at max_cache_entry_bytes is admissible when the documented
        // constructor relationship holds.
        let negative_bytes = negative_entries
            .saturating_mul(fixed_entry_retained_bytes())
            .min(entry_bytes);
        let active_bytes = entry_bytes.saturating_sub(negative_bytes);
        let budget = Self {
            active: ClassBudget::new(active_entries, active_bytes),
            negative: ClassBudget::new(negative_entries, negative_bytes),
        };
        let metrics = crate::plugins::prometheus_metrics::global_registry();
        metrics.adjust_oauth2_introspection_cache_retention(
            EntryClass::Active.metric_label(),
            0,
            budget.active.fixed_index_bytes as i64,
        );
        metrics.adjust_oauth2_introspection_cache_retention(
            EntryClass::Negative.metric_label(),
            0,
            budget.negative.fixed_index_bytes as i64,
        );
        budget
    }

    fn class(&self, class: EntryClass) -> &ClassBudget {
        match class {
            EntryClass::Active => &self.active,
            EntryClass::Negative => &self.negative,
        }
    }

    fn try_reserve(
        self: &Arc<Self>,
        class: EntryClass,
        retained_bytes: usize,
    ) -> Result<AdmissionReservation, AdmissionFailure> {
        let budget = self.class(class);
        if budget
            .entries
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |entries| {
                entries
                    .checked_add(1)
                    .filter(|next| *next <= budget.max_entries)
            })
            .is_err()
        {
            return Err(AdmissionFailure::EntryCount);
        }
        if budget
            .retained_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |bytes| {
                bytes
                    .checked_add(retained_bytes)
                    .filter(|next| *next <= budget.max_retained_bytes)
            })
            .is_err()
        {
            release_atomic(&budget.entries, 1, "entry");
            return Err(AdmissionFailure::TotalBytes);
        }
        crate::plugins::prometheus_metrics::global_registry()
            .adjust_oauth2_introspection_cache_retention(
                class.metric_label(),
                1,
                retained_bytes as i64,
            );
        Ok(AdmissionReservation {
            budget: Arc::clone(self),
            class,
            retained_bytes,
        })
    }
}

impl Drop for CacheBudget {
    fn drop(&mut self) {
        let metrics = crate::plugins::prometheus_metrics::global_registry();
        metrics.adjust_oauth2_introspection_cache_retention(
            EntryClass::Active.metric_label(),
            0,
            -(self.active.fixed_index_bytes as i64),
        );
        metrics.adjust_oauth2_introspection_cache_retention(
            EntryClass::Negative.metric_label(),
            0,
            -(self.negative.fixed_index_bytes as i64),
        );
    }
}

struct AdmissionReservation {
    budget: Arc<CacheBudget>,
    class: EntryClass,
    retained_bytes: usize,
}

impl Drop for AdmissionReservation {
    fn drop(&mut self) {
        let budget = self.budget.class(self.class);
        release_atomic(&budget.entries, 1, "entry");
        release_atomic(&budget.retained_bytes, self.retained_bytes, "retained-byte");
        crate::plugins::prometheus_metrics::global_registry()
            .adjust_oauth2_introspection_cache_retention(
                self.class.metric_label(),
                -1,
                -(self.retained_bytes as i64),
            );
    }
}

#[derive(Clone, Copy)]
enum AdmissionFailure {
    EntryCount,
    TotalBytes,
}

enum TicketWork {
    Removed,
    Retained,
    Stale,
    Empty,
}

struct AdmissionGuard<'a> {
    active: &'a AtomicBool,
}

impl Drop for AdmissionGuard<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

impl AdmissionFailure {
    fn metric_label(self) -> &'static str {
        match self {
            Self::EntryCount => "entry_count",
            Self::TotalBytes => "total_bytes",
        }
    }
}

pub struct IntrospectionCache {
    entries: DashMap<TokenKey, Entry>,
    budget: Arc<CacheBudget>,
    max_entry_bytes: usize,
    positive_ttl: Duration,
    negative_ttl: Duration,
    active_tickets: ArrayQueue<EvictionTicket>,
    negative_tickets: ArrayQueue<EvictionTicket>,
    next_generation: AtomicU64,
    /// Cache admission never waits behind another miss completion. Contention
    /// skips retention while preserving the provider's successful result.
    admission_active: [AtomicBool; 2],
}

impl IntrospectionCache {
    pub fn minimum_total_bytes(max_entries: usize) -> usize {
        max_entries.saturating_mul(
            size_of::<EvictionTicket>().saturating_add(fixed_entry_retained_bytes()),
        )
    }

    pub fn new(
        max_entries: usize,
        max_entry_bytes: usize,
        max_total_bytes: usize,
        positive_ttl: Duration,
        negative_ttl: Duration,
        shard_amount: usize,
    ) -> Self {
        let budget = Arc::new(CacheBudget::new(max_entries.max(2), max_total_bytes));
        Self {
            entries: DashMap::with_shard_amount(shard_amount),
            active_tickets: ArrayQueue::new(budget.active.max_entries),
            negative_tickets: ArrayQueue::new(budget.negative.max_entries),
            budget,
            max_entry_bytes,
            positive_ttl,
            negative_ttl,
            next_generation: AtomicU64::new(1),
            admission_active: std::array::from_fn(|_| AtomicBool::new(false)),
        }
    }

    pub fn get(&self, token: &str, now: Instant) -> CacheLookup {
        let key = TokenKey::from_token(token);
        let Some(entry) = self.entries.get(&key) else {
            return CacheLookup::Miss;
        };
        if entry.expires_at > now {
            entry.recently_used.store(true, Ordering::Relaxed);
            return match &entry.value {
                EntryValue::Active(authorization) => CacheLookup::Active(Arc::clone(authorization)),
                EntryValue::Negative => CacheLookup::Negative,
            };
        }
        let generation = entry.generation;
        let class = entry.class();
        drop(entry);
        if self
            .entries
            .remove_if(&key, |_, current| current.generation == generation)
            .is_some()
        {
            crate::plugins::prometheus_metrics::global_registry()
                .record_oauth2_introspection_cache_eviction(class.metric_label(), "expired");
        }
        CacheLookup::Miss
    }

    pub fn insert_active(
        &self,
        token: &str,
        authorization: Arc<CachedAuthorization>,
        now: Instant,
        exp: Option<i64>,
    ) -> bool {
        if self.positive_ttl.is_zero() {
            return false;
        }
        let payload_bytes = authorization.retained_bytes();
        if payload_bytes > self.max_entry_bytes {
            self.record_admission_skip(EntryClass::Active, "entry_bytes");
            return false;
        }
        let Some(mut expires_at) = now.checked_add(self.positive_ttl) else {
            self.record_admission_skip(EntryClass::Active, "expiry");
            return false;
        };
        if let Some(exp) = exp {
            let unix_now = chrono::Utc::now().timestamp();
            let Ok(seconds) = u64::try_from(exp.saturating_sub(unix_now)) else {
                self.record_admission_skip(EntryClass::Active, "expiry");
                return false;
            };
            if seconds == 0 {
                self.record_admission_skip(EntryClass::Active, "expiry");
                return false;
            }
            let Some(exp_deadline) = now.checked_add(Duration::from_secs(seconds)) else {
                self.record_admission_skip(EntryClass::Active, "expiry");
                return false;
            };
            expires_at = expires_at.min(exp_deadline);
        }
        let retained_bytes = size_of::<TokenKey>()
            .saturating_add(size_of::<Entry>())
            .saturating_add(payload_bytes);
        self.insert(
            TokenKey::from_token(token),
            EntryClass::Active,
            EntryValue::Active(authorization),
            expires_at,
            retained_bytes,
            now,
        )
    }

    pub fn insert_negative(&self, token: &str, now: Instant) -> bool {
        if self.negative_ttl.is_zero() {
            return false;
        }
        let Some(expires_at) = now.checked_add(self.negative_ttl) else {
            self.record_admission_skip(EntryClass::Negative, "expiry");
            return false;
        };
        let retained_bytes = size_of::<TokenKey>().saturating_add(size_of::<Entry>());
        self.insert(
            TokenKey::from_token(token),
            EntryClass::Negative,
            EntryValue::Negative,
            expires_at,
            retained_bytes,
            now,
        )
    }

    fn insert(
        &self,
        key: TokenKey,
        class: EntryClass,
        value: EntryValue,
        expires_at: Instant,
        retained_bytes: usize,
        now: Instant,
    ) -> bool {
        let _admission = match self.try_begin_admission(class) {
            Some(guard) => guard,
            None => {
                self.record_admission_skip(class, "contention");
                return false;
            }
        };
        if self.entries.contains_key(&key) {
            self.record_admission_skip(class, "superseded");
            return false;
        }

        let mut work = 0usize;
        let mut reservation = self.budget.try_reserve(class, retained_bytes);
        while reservation.is_err() && work < EVICTION_WORK_LIMIT {
            if matches!(self.examine_one_ticket(class, now), TicketWork::Empty) {
                break;
            }
            work += 1;
            reservation = self.budget.try_reserve(class, retained_bytes);
        }
        let reservation = match reservation {
            Ok(reservation) => reservation,
            Err(failure) => {
                self.record_admission_skip(class, failure.metric_label());
                return false;
            }
        };

        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let mut ticket = EvictionTicket {
            key: key.clone(),
            generation,
        };
        let mut ticket_published = false;
        loop {
            match self.ticket_queue(class).push(ticket) {
                Ok(()) => {
                    ticket_published = true;
                    break;
                }
                Err(returned) => {
                    ticket = returned;
                    if work >= EVICTION_WORK_LIMIT {
                        break;
                    }
                    if matches!(self.examine_one_ticket(class, now), TicketWork::Empty) {
                        break;
                    }
                    work += 1;
                }
            }
        }
        if !ticket_published {
            self.record_admission_skip(class, "eviction_index");
            return false;
        }
        match self.entries.entry(key) {
            DashEntry::Vacant(vacant) => {
                vacant.insert(Entry {
                    value,
                    expires_at,
                    generation,
                    recently_used: AtomicBool::new(true),
                    _reservation: reservation,
                });
                true
            }
            DashEntry::Occupied(_) => {
                self.record_admission_skip(class, "superseded");
                false
            }
        }
    }

    fn examine_one_ticket(&self, class: EntryClass, now: Instant) -> TicketWork {
        let queue = self.ticket_queue(class);
        let Some(ticket) = queue.pop() else {
            return TicketWork::Empty;
        };
        crate::plugins::prometheus_metrics::global_registry()
            .record_oauth2_introspection_cache_cleanup_work();
        let Some(entry) = self.entries.get(&ticket.key) else {
            return TicketWork::Stale;
        };
        if entry.generation != ticket.generation || entry.class() != class {
            return TicketWork::Stale;
        }
        let expired = entry.expires_at <= now;
        if !expired && entry.recently_used.swap(false, Ordering::AcqRel) {
            drop(entry);
            if let Err(ticket) = queue.push(ticket) {
                let _ = self.remove_ticket_entry(&ticket, class, "capacity");
                return TicketWork::Removed;
            }
            return TicketWork::Retained;
        }
        drop(entry);
        let reason = if expired { "expired" } else { "capacity" };
        if self.remove_ticket_entry(&ticket, class, reason) {
            TicketWork::Removed
        } else {
            TicketWork::Stale
        }
    }

    fn remove_ticket_entry(
        &self,
        ticket: &EvictionTicket,
        class: EntryClass,
        reason: &'static str,
    ) -> bool {
        let removed = self
            .entries
            .remove_if(&ticket.key, |_, current| {
                current.generation == ticket.generation && current.class() == class
            })
            .is_some();
        if removed {
            crate::plugins::prometheus_metrics::global_registry()
                .record_oauth2_introspection_cache_eviction(class.metric_label(), reason);
        }
        removed
    }

    fn ticket_queue(&self, class: EntryClass) -> &ArrayQueue<EvictionTicket> {
        match class {
            EntryClass::Active => &self.active_tickets,
            EntryClass::Negative => &self.negative_tickets,
        }
    }

    fn try_begin_admission(&self, class: EntryClass) -> Option<AdmissionGuard<'_>> {
        let active = &self.admission_active[class.index()];
        active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| AdmissionGuard { active })
    }

    fn record_admission_skip(&self, class: EntryClass, reason: &'static str) {
        crate::plugins::prometheus_metrics::global_registry()
            .record_oauth2_introspection_cache_admission_skip(class.metric_label(), reason);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn retained_bytes(&self) -> usize {
        self.budget
            .active
            .retained_bytes
            .load(Ordering::Acquire)
            .saturating_add(self.budget.negative.retained_bytes.load(Ordering::Acquire))
    }
}

fn release_atomic(counter: &AtomicUsize, amount: usize, kind: &'static str) {
    let mut underflow = false;
    let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        underflow = current < amount;
        Some(current.saturating_sub(amount))
    });
    if underflow {
        warn!(
            plugin = "oauth2_introspection",
            "introspection cache {kind} accounting underflow prevented"
        );
    }
}

fn fixed_entry_retained_bytes() -> usize {
    size_of::<TokenKey>().saturating_add(size_of::<Entry>())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization(payload_bytes: usize) -> Arc<CachedAuthorization> {
        Arc::new(CachedAuthorization {
            authorization_error: None,
            identity: Some("x".repeat(payload_bytes).into_boxed_str()),
            identity_header: None,
            claim_headers: Box::default(),
        })
    }

    fn cache(
        max_entries: usize,
        max_entry_bytes: usize,
        max_total_bytes: usize,
    ) -> IntrospectionCache {
        IntrospectionCache::new(
            max_entries,
            max_entry_bytes,
            max_total_bytes,
            Duration::from_secs(60),
            Duration::from_secs(60),
            4,
        )
    }

    #[test]
    fn cache_key_hash_does_not_store_raw_token() {
        let key = TokenKey::from_token("secret-token");
        assert_ne!(key.digest().as_slice(), b"secret-token");
    }

    #[test]
    fn positive_cache_expires_and_releases_bytes() {
        let cache = cache(100, 4096, 1024 * 1024);
        let now = Instant::now();
        assert!(cache.insert_active("token", authorization(32), now, None));
        assert!(cache.retained_bytes() > 0);
        assert!(matches!(cache.get("token", now), CacheLookup::Active(_)));
        assert!(matches!(
            cache.get("token", now + Duration::from_secs(61)),
            CacheLookup::Miss
        ));
        assert_eq!(cache.retained_bytes(), 0);
    }

    #[test]
    fn oversized_active_result_is_not_retained() {
        let cache = cache(100, 256, 1024 * 1024);
        assert!(!cache.insert_active("token", authorization(512), Instant::now(), None));
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.retained_bytes(), 0);
    }

    #[test]
    fn per_entry_limit_is_inclusive() {
        let candidate = authorization(64);
        let exact = candidate.retained_bytes();
        let exact_cache = cache(100, exact, 1024 * 1024);
        assert!(exact_cache.insert_active("exact", candidate, Instant::now(), None));

        let oversized = authorization(64);
        let smaller_cache = cache(100, exact - 1, 1024 * 1024);
        assert!(!smaller_cache.insert_active("one-byte-over", oversized, Instant::now(), None,));
    }

    #[test]
    fn concurrent_inserts_never_exceed_count_or_byte_capacity() {
        let cache = Arc::new(cache(100, 4096, 1024 * 1024));
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let cache = Arc::clone(&cache);
                scope.spawn(move || {
                    for token in 0_u64..100 {
                        let name = format!("worker-{worker}-token-{token}");
                        if token.is_multiple_of(2) {
                            cache.insert_active(&name, authorization(64), Instant::now(), None);
                        } else {
                            cache.insert_negative(&name, Instant::now());
                        }
                    }
                });
            }
        });
        assert!(cache.len() <= 100);
        assert!(cache.retained_bytes() <= 1024 * 1024);
    }

    #[test]
    fn same_key_races_publish_one_reservation() {
        let cache = Arc::new(cache(100, 4096, 1024 * 1024));
        let budget = Arc::downgrade(&cache.budget);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let cache = Arc::clone(&cache);
                scope.spawn(move || {
                    cache.insert_active("same", authorization(64), Instant::now(), None);
                });
            }
        });
        assert_eq!(cache.len(), 1);
        let retained = cache.retained_bytes();
        drop(cache);
        assert!(retained > 0);
        assert!(budget.upgrade().is_none());
    }

    #[test]
    fn retired_generation_releases_reservations_while_result_is_in_flight() {
        let cache = Arc::new(cache(100, 4096, 1024 * 1024));
        let budget = Arc::downgrade(&cache.budget);
        let now = Instant::now();
        assert!(cache.insert_active("in-flight", authorization(64), now, None));
        let result = match cache.get("in-flight", now) {
            CacheLookup::Active(result) => result,
            _ => panic!("active result must be present"),
        };

        drop(cache);

        assert!(budget.upgrade().is_none());
        assert_eq!(result.identity.as_deref().map(str::len), Some(64));
    }

    #[test]
    fn negative_churn_cannot_evict_active_entries() {
        let cache = cache(100, 4096, 1024 * 1024);
        let now = Instant::now();
        assert!(cache.insert_active("hot", authorization(64), now, None));
        for token in 0..1000 {
            cache.insert_negative(&format!("inactive-{token}"), now);
        }
        assert!(matches!(cache.get("hot", now), CacheLookup::Active(_)));
    }

    #[test]
    fn active_churn_cannot_evict_negative_entries() {
        let cache = cache(100, 4096, 1024 * 1024);
        let now = Instant::now();
        assert!(cache.insert_negative("inactive-hot", now));
        for token in 0..1000 {
            cache.insert_active(&format!("active-{token}"), authorization(64), now, None);
        }
        assert!(matches!(
            cache.get("inactive-hot", now),
            CacheLookup::Negative
        ));
    }
}
