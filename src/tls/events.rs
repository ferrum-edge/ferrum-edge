//! Bounded TLS source rotation event log.
//!
//! This log captures background source watcher outcomes without storing PEM
//! bytes. It keeps a bounded in-memory ring and persists the same bounded event
//! set beside the managed TLS store so recent rotation history survives process
//! restarts.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::fips::approved::Sha256;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::tls::shared_store::{
    TlsPersistentStoreKind, TlsStoreIoDirection, open_authoritative_document_file,
    read_bounded_document_bytes, record_store_record_count,
    validate_explicit_store_max_document_bytes,
};
use crate::tls::source::subscription::{MaterialFingerprintEntry, WatchedMaterialSource};
use crate::tls::source::{CertSource, MaterialKind, SourceScheme};

const DEFAULT_EVENT_CAPACITY: usize = 1024;
#[cfg(not(test))]
const EVENT_LOG_FILE_NAME: &str = "tls-events.json";
#[cfg(not(test))]
const DEFAULT_EVENT_STORE_DIR: &str = "./ferrum-managed-tls";

static TLS_EVENT_LOG: OnceLock<TlsEventLog> = OnceLock::new();

pub fn global_event_log() -> &'static TlsEventLog {
    #[cfg(test)]
    {
        TLS_EVENT_LOG.get_or_init(|| TlsEventLog::new(DEFAULT_EVENT_CAPACITY))
    }

    #[cfg(not(test))]
    TLS_EVENT_LOG.get_or_init(|| {
        let path = persistent_event_log_path();
        TlsEventLog::open(DEFAULT_EVENT_CAPACITY, Some(path)).unwrap_or_else(|error| {
            warn!(
                error = %error,
                "Failed to open persistent TLS event log; falling back to process-local history"
            );
            TlsEventLog::new(DEFAULT_EVENT_CAPACITY)
        })
    })
}

/// Non-initializing accessor for the process event log.
///
/// [`global_event_log`] creates and persists the on-disk event store on first
/// use. Read-only consumers that merely *observe* rotation state — the cached
/// TLS inventory snapshot — must not create that store as a side effect, so
/// they take this accessor and treat "no log yet" as "no recorded failure".
pub fn event_log_if_initialized() -> Option<&'static TlsEventLog> {
    TLS_EVENT_LOG.get()
}

/// Latest recorded failure for a configured source identity.
#[derive(Debug, Clone)]
pub struct TlsSourceFailure {
    /// Recorded event outcome (`load_error` or `rebuild_error`).
    pub outcome: String,
    /// Sanitized failure detail as recorded by the producer.
    pub error: Option<String>,
    pub at: DateTime<Utc>,
}

/// Return the most recent event naming `source_id` when — and only when — that
/// event was a failure. A later success clears the failure, so a rotated source
/// stops reporting a stale error without re-reading its material.
pub fn latest_source_failure(source_id: &str) -> Option<TlsSourceFailure> {
    let event = event_log_if_initialized()?.latest_for_source(source_id)?;
    match event.outcome.as_str() {
        "load_error" | "rebuild_error" => Some(TlsSourceFailure {
            outcome: event.outcome,
            error: event.error,
            at: event.at,
        }),
        _ => None,
    }
}

#[derive(Debug, Clone, Default)]
pub struct TlsEventFilter {
    pub cert_id: Option<String>,
    pub source_id: Option<String>,
    pub surface: Option<String>,
    pub outcome: Option<String>,
    pub since: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSourceEvent {
    pub id: u64,
    pub at: DateTime<Utc>,
    pub surface: String,
    pub outcome: String,
    pub sources: Vec<TlsSourceEventMaterial>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSourceEventMaterial {
    pub label: String,
    pub cert_id: String,
    pub source_id: String,
    pub scheme: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_sha256: Option<String>,
}

pub struct TlsEventLog {
    capacity: usize,
    next_id: AtomicU64,
    events: Mutex<VecDeque<TlsSourceEvent>>,
    path: Option<PathBuf>,
    max_document_bytes: usize,
}

impl TlsEventLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            next_id: AtomicU64::new(1),
            events: Mutex::new(VecDeque::new()),
            path: None,
            max_document_bytes: crate::config::env_config::DEFAULT_TLS_STORE_MAX_DOCUMENT_BYTES,
        }
    }

    pub fn open(capacity: usize, path: Option<PathBuf>) -> Result<Self, String> {
        let capacity = capacity.max(1);
        let Some(path) = path else {
            return Ok(Self::new(capacity));
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let max_document_bytes =
            crate::config::env_config::tls_store_max_document_bytes_from_env()?;
        let mut events = load_event_log_events(&path, max_document_bytes)?;
        while events.len() > capacity {
            events.pop_front();
        }
        let next_id = events
            .iter()
            .map(|event| event.id)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
            .max(1);
        let log = Self {
            capacity,
            next_id: AtomicU64::new(next_id),
            events: Mutex::new(events),
            path: Some(path),
            max_document_bytes,
        };
        // Compact atomically to the configured capacity so a legacy oversized
        // entry count (still within the byte ceiling) shrinks on disk.
        log.persist_snapshot()?;
        record_store_record_count(
            TlsPersistentStoreKind::Events,
            log.events
                .lock()
                .map(|events| events.len() as u64)
                .unwrap_or(0),
        );
        Ok(log)
    }

    /// Open with an explicit document ceiling (tests).
    #[allow(dead_code)] // External unit tests; production uses open.
    pub fn open_with_document_limit(
        capacity: usize,
        path: Option<PathBuf>,
        max_document_bytes: usize,
    ) -> Result<Self, String> {
        let capacity = capacity.max(1);
        let max_document_bytes = validate_explicit_store_max_document_bytes(max_document_bytes)
            .map_err(|error| error.to_string())?;
        let Some(path) = path else {
            return Ok(Self {
                capacity,
                next_id: AtomicU64::new(1),
                events: Mutex::new(VecDeque::new()),
                path: None,
                max_document_bytes,
            });
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let mut events = load_event_log_events(&path, max_document_bytes)?;
        while events.len() > capacity {
            events.pop_front();
        }
        let next_id = events
            .iter()
            .map(|event| event.id)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
            .max(1);
        let log = Self {
            capacity,
            next_id: AtomicU64::new(next_id),
            events: Mutex::new(events),
            path: Some(path),
            max_document_bytes,
        };
        log.persist_snapshot()?;
        record_store_record_count(
            TlsPersistentStoreKind::Events,
            log.events
                .lock()
                .map(|events| events.len() as u64)
                .unwrap_or(0),
        );
        Ok(log)
    }

    pub fn record(&self, mut event: TlsSourceEvent) {
        // Allocate the id before building the candidate. Gaps after a refused
        // persist are acceptable; the deque must stay untouched until durable
        // publication succeeds.
        event.id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let Ok(mut events) = self.events.lock() else {
            return;
        };
        let mut candidate = events.clone();
        candidate.push_back(event);
        while candidate.len() > self.capacity {
            candidate.pop_front();
        }
        if let Err(error) = self.persist_locked(&candidate) {
            warn!(
                error = %error,
                "Failed to persist TLS source rotation event"
            );
            // Leave the prior in-memory deque exactly unchanged so a refused
            // oversized/I/O candidate cannot evict durable history from cache.
            return;
        }
        *events = candidate;
        record_store_record_count(TlsPersistentStoreKind::Events, events.len() as u64);
    }

    pub fn list(&self, filter: &TlsEventFilter) -> Vec<TlsSourceEvent> {
        let Ok(events) = self.events.lock() else {
            return Vec::new();
        };
        events
            .iter()
            .filter(|event| event_matches(event, filter))
            .cloned()
            .collect()
    }

    /// Newest event naming `source_id`, or `None` when the source has no
    /// recorded rotation history.
    pub fn latest_for_source(&self, source_id: &str) -> Option<TlsSourceEvent> {
        let events = self.events.lock().ok()?;
        for event in events.iter().rev() {
            if event.sources.iter().any(|s| s.source_id == source_id) {
                return Some(event.clone());
            }
        }
        None
    }

    fn persist_snapshot(&self) -> Result<(), String> {
        let events = self
            .events
            .lock()
            .map_err(|_| "TLS event log lock is poisoned".to_string())?;
        self.persist_locked(&events)
    }

    fn persist_locked(&self, events: &VecDeque<TlsSourceEvent>) -> Result<(), String> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        let payload = serde_json::to_vec_pretty(&TlsEventLogFile {
            events: events.iter().cloned().collect(),
        })
        .map_err(|error| error.to_string())?;
        if payload.len() > self.max_document_bytes {
            crate::plugins::prometheus_metrics::global_registry().record_tls_store_oversized(
                TlsPersistentStoreKind::Events,
                TlsStoreIoDirection::Write,
            );
            return Err(format!(
                "TLS event log document exceeds the configured byte ceiling (max {} bytes)",
                self.max_document_bytes
            ));
        }
        write_private_file_atomic(path, &payload)?;
        crate::plugins::prometheus_metrics::global_registry()
            .set_tls_store_document_bytes(TlsPersistentStoreKind::Events, payload.len() as u64);
        Ok(())
    }
}

fn load_event_log_events(
    path: &Path,
    max_document_bytes: usize,
) -> Result<VecDeque<TlsSourceEvent>, String> {
    let mut file = match open_authoritative_document_file(path) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(VecDeque::new()),
        Err(error) => return Err(error.to_string()),
    };
    if let Ok(metadata) = file.metadata()
        && metadata.len() > max_document_bytes as u64
    {
        crate::plugins::prometheus_metrics::global_registry()
            .record_tls_store_oversized(TlsPersistentStoreKind::Events, TlsStoreIoDirection::Read);
        return Err(format!(
            "TLS event log document exceeds the configured byte ceiling (max {max_document_bytes} bytes)"
        ));
    }
    let bytes = match read_bounded_document_bytes(&mut file, path, max_document_bytes) {
        Ok(bytes) => bytes,
        Err(crate::tls::shared_store::SharedStoreError::Oversized { .. }) => {
            crate::plugins::prometheus_metrics::global_registry().record_tls_store_oversized(
                TlsPersistentStoreKind::Events,
                TlsStoreIoDirection::Read,
            );
            return Err(format!(
                "TLS event log document exceeds the configured byte ceiling (max {max_document_bytes} bytes)"
            ));
        }
        Err(error) => return Err(error.to_string()),
    };
    crate::plugins::prometheus_metrics::global_registry()
        .set_tls_store_document_bytes(TlsPersistentStoreKind::Events, bytes.len() as u64);
    let parsed = serde_json::from_slice::<TlsEventLogFile>(&bytes)
        .map_err(|_error| "TLS event log is malformed".to_string())?;
    Ok(parsed.events.into_iter().collect())
}

#[derive(Debug, Serialize, Deserialize)]
struct TlsEventLogFile {
    #[serde(default)]
    events: Vec<TlsSourceEvent>,
}

pub fn record_rotation_success(
    surface: &'static str,
    entries: &[MaterialFingerprintEntry],
    revision: u64,
) {
    let sources = entries
        .iter()
        .map(event_material_from_entry)
        .collect::<Vec<_>>();
    record_rotation_metrics(&sources, "source_refresh", "success");
    global_event_log().record(TlsSourceEvent {
        id: 0,
        at: Utc::now(),
        surface: surface.to_string(),
        outcome: "rotated".to_string(),
        sources,
        revision: Some(revision),
        error: None,
    });
    // Rotated material changes the public certificate metadata the cached
    // metrics snapshot exports, so let the next scrape refresh it immediately
    // instead of waiting out the snapshot TTL.
    crate::tls::inventory_cache::mark_stale();
}

pub fn record_rebuild_error(
    surface: &'static str,
    entries: &[MaterialFingerprintEntry],
    error: &anyhow::Error,
) {
    let sources = entries
        .iter()
        .map(event_material_from_entry)
        .collect::<Vec<_>>();
    record_rotation_metrics(&sources, "source_refresh", "failure");
    global_event_log().record(TlsSourceEvent {
        id: 0,
        at: Utc::now(),
        surface: surface.to_string(),
        outcome: "rebuild_error".to_string(),
        sources,
        revision: None,
        error: Some(error.to_string()),
    });
    // A recorded failure is the owning reload state the cached snapshot reports
    // key/JWKS/OCSP health from; refresh it on the next scrape.
    crate::tls::inventory_cache::mark_stale();
}

pub fn record_load_error(surface: &'static str, sources: &[WatchedMaterialSource], error: &str) {
    let sources = sources
        .iter()
        .map(event_material_from_source)
        .collect::<Vec<_>>();
    record_rotation_metrics(&sources, "source_refresh", "failure");
    global_event_log().record(TlsSourceEvent {
        id: 0,
        at: Utc::now(),
        surface: surface.to_string(),
        outcome: "load_error".to_string(),
        sources,
        revision: None,
        error: Some(error.to_string()),
    });
    // A recorded failure is the owning reload state the cached snapshot reports
    // key/JWKS/OCSP health from; refresh it on the next scrape.
    crate::tls::inventory_cache::mark_stale();
}

fn record_rotation_metrics(
    sources: &[TlsSourceEventMaterial],
    reason: &'static str,
    outcome: &'static str,
) {
    let registry = crate::plugins::prometheus_metrics::global_registry();
    for source in sources {
        if source.kind == MaterialKind::Cert.as_str() {
            registry.record_tls_cert_rotation(&source.cert_id, reason, outcome);
        }
    }
}

fn event_matches(event: &TlsSourceEvent, filter: &TlsEventFilter) -> bool {
    if let Some(since) = filter.since
        && event.at < since
    {
        return false;
    }
    if let Some(surface) = filter.surface.as_deref()
        && event.surface != surface
    {
        return false;
    }
    if let Some(outcome) = filter.outcome.as_deref()
        && event.outcome != outcome
    {
        return false;
    }
    if let Some(cert_id) = filter.cert_id.as_deref()
        && !event.sources.iter().any(|source| source.cert_id == cert_id)
    {
        return false;
    }
    if let Some(source_id) = filter.source_id.as_deref()
        && !event
            .sources
            .iter()
            .any(|source| source.source_id == source_id)
    {
        return false;
    }
    true
}

fn event_material_from_entry(entry: &MaterialFingerprintEntry) -> TlsSourceEventMaterial {
    TlsSourceEventMaterial {
        label: entry.label.to_string(),
        cert_id: event_cert_id(entry.kind, &entry.source_id),
        source_id: entry.source_id.clone(),
        scheme: entry.source_kind.as_str().to_string(),
        kind: entry.kind.as_str().to_string(),
        fingerprint_sha256: non_secret_fingerprint(entry.kind, entry.fingerprint),
    }
}

fn event_material_from_source(source: &WatchedMaterialSource) -> TlsSourceEventMaterial {
    let source_id = source.source.source_id();
    TlsSourceEventMaterial {
        label: source.label.to_string(),
        cert_id: event_cert_id(source.kind, &source.source.pool_key_component()),
        source_id,
        scheme: configured_source_scheme(&source.source)
            .as_str()
            .to_string(),
        kind: source.kind.as_str().to_string(),
        fingerprint_sha256: None,
    }
}

fn event_cert_id(kind: MaterialKind, source_key: &str) -> String {
    let digest = Sha256::digest(format!("{}|{}", kind.as_str(), source_key).as_bytes());
    format!("{}-{}", kind.as_str(), hex::encode(&digest[..8]))
}

fn non_secret_fingerprint(kind: MaterialKind, fingerprint: [u8; 32]) -> Option<String> {
    if kind == MaterialKind::Key {
        return None;
    }
    Some(hex::encode(fingerprint))
}

fn configured_source_scheme(source: &CertSource) -> SourceScheme {
    match source {
        CertSource::Path(_) | CertSource::InlinePem(_) => SourceScheme::File,
        CertSource::Uri(uri) => uri.scheme,
    }
}

#[cfg(not(test))]
fn persistent_event_log_path() -> PathBuf {
    let dir = crate::config::env_config::tls_managed_store_path_from_env();
    let dir = if dir.is_empty() {
        PathBuf::from(DEFAULT_EVENT_STORE_DIR)
    } else {
        PathBuf::from(dir)
    };
    dir.join(EVENT_LOG_FILE_NAME)
}

fn write_private_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "TLS event log path has no parent directory".to_string())?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    crate::tls::private_file::replace_private_file(path, bytes).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_with(id: u64, surface: &str, outcome: &str, cert_id: &str) -> TlsSourceEvent {
        TlsSourceEvent {
            id,
            at: Utc::now(),
            surface: surface.to_string(),
            outcome: outcome.to_string(),
            sources: vec![TlsSourceEventMaterial {
                label: "cert".to_string(),
                cert_id: cert_id.to_string(),
                source_id: "/tmp/cert.pem".to_string(),
                scheme: "file".to_string(),
                kind: "cert".to_string(),
                fingerprint_sha256: Some("abc".to_string()),
            }],
            revision: Some(1),
            error: None,
        }
    }

    #[test]
    fn event_log_is_bounded_and_filterable() {
        let log = TlsEventLog::new(2);
        log.record(event_with(0, "proxy_https", "rotated", "cert-a"));
        log.record(event_with(0, "admin_https", "rotated", "cert-b"));
        log.record(event_with(0, "proxy_https", "load_error", "cert-a"));

        let all = log.list(&TlsEventFilter::default());
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].surface, "admin_https");
        assert_eq!(all[1].outcome, "load_error");

        let filtered = log.list(&TlsEventFilter {
            cert_id: Some("cert-a".to_string()),
            surface: Some("proxy_https".to_string()),
            ..Default::default()
        });
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].outcome, "load_error");
    }

    #[test]
    fn private_key_event_material_omits_fingerprint() {
        assert!(non_secret_fingerprint(MaterialKind::Key, [1; 32]).is_none());
        assert!(non_secret_fingerprint(MaterialKind::Cert, [1; 32]).is_some());
    }

    #[test]
    fn event_log_persists_bounded_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tls-events.json");
        let log = TlsEventLog::open(2, Some(path.clone())).expect("open log");

        log.record(event_with(0, "proxy_https", "rotated", "cert-a"));
        log.record(event_with(0, "admin_https", "rotated", "cert-b"));
        log.record(event_with(0, "proxy_https", "load_error", "cert-c"));

        let reloaded = TlsEventLog::open(2, Some(path)).expect("reload log");
        let events = reloaded.list(&TlsEventFilter::default());
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sources[0].cert_id, "cert-b");
        assert_eq!(events[1].sources[0].cert_id, "cert-c");

        reloaded.record(event_with(0, "proxy_https", "rotated", "cert-d"));
        let events = reloaded.list(&TlsEventFilter::default());
        assert_eq!(events[1].id, 4);
    }
}
