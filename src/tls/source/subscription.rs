//! Source-set polling substrate for TLS material reloads.
//!
//! This is intentionally material-agnostic: a caller provides the configured
//! sources and a surface-specific rebuild closure. The loop fingerprints the
//! material bytes, not file mtimes, so atomic rewrites with identical bytes do
//! not churn TLS configs or connection pools.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures_util::TryStreamExt;
use futures_util::future::BoxFuture;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::{
    CertSource, MaterialError, MaterialKind, SourceScheme, k8s_secret_watch_target,
    load_material_blocking,
};

pub const DEFAULT_SECRET_REFRESH_INTERVAL_SECS: u64 = 300;
const MAX_SOURCE_POLL_INTERVAL_SECS: u64 = 86_400;
static FORCE_RELOAD_REGISTRY: OnceLock<DashMap<&'static str, mpsc::Sender<()>>> = OnceLock::new();

fn force_reload_registry() -> &'static DashMap<&'static str, mpsc::Sender<()>> {
    FORCE_RELOAD_REGISTRY.get_or_init(DashMap::new)
}

pub fn registered_material_set_reload_surfaces() -> Vec<&'static str> {
    let mut surfaces = force_reload_registry()
        .iter()
        .map(|entry| *entry.key())
        .collect::<Vec<_>>();
    surfaces.sort_unstable();
    surfaces
}

pub fn request_material_set_reload(surface: &str) -> bool {
    let send_result = force_reload_registry()
        .get(surface)
        .map(|sender| sender.try_send(()));
    match send_result {
        Some(Ok(())) => true,
        Some(Err(TrySendError::Full(_))) => true,
        Some(Err(TrySendError::Closed(_))) => {
            force_reload_registry().remove(surface);
            false
        }
        None => false,
    }
}

pub fn request_all_material_set_reloads() -> Vec<&'static str> {
    let surfaces = registered_material_set_reload_surfaces();
    surfaces
        .into_iter()
        .filter(|surface| request_material_set_reload(surface))
        .collect()
}

/// One configured material source to include in a reload fingerprint.
#[derive(Clone)]
pub struct WatchedMaterialSource {
    pub label: &'static str,
    pub source: CertSource,
    pub kind: MaterialKind,
}

impl WatchedMaterialSource {
    pub fn new(label: &'static str, source: CertSource, kind: MaterialKind) -> Self {
        Self {
            label,
            source,
            kind,
        }
    }

    #[allow(dead_code)]
    pub fn source_id(&self) -> String {
        self.source.source_id()
    }
}

/// A non-secret byte fingerprint for one material source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterialFingerprintEntry {
    pub label: &'static str,
    pub source_id: String,
    pub fingerprint: [u8; 32],
    pub version: Option<String>,
    pub source_kind: SourceScheme,
    pub kind: MaterialKind,
}

/// Combined source-set fingerprint. Equality is the rotation predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterialSetFingerprint {
    pub entries: Vec<MaterialFingerprintEntry>,
}

impl MaterialSetFingerprint {
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Return true when the source can change underneath the running process.
///
/// Inline PEM is static until the config itself is reloaded. File paths and
/// `file://` sources can rotate in place. Provider URIs are refreshable when
/// their backing loader can materialize them.
pub fn source_is_refreshable(source: &CertSource) -> bool {
    match source {
        CertSource::Path(_) => true,
        CertSource::InlinePem(_) => false,
        CertSource::Uri(uri) => matches!(
            uri.scheme,
            SourceScheme::File
                | SourceScheme::Vault
                | SourceScheme::Aws
                | SourceScheme::Azure
                | SourceScheme::Gcp
                | SourceScheme::K8sSecret
                | SourceScheme::Acme
                | SourceScheme::Managed
        ),
    }
}

/// Effective polling interval for a material source set.
///
/// A set uses the smallest interval among refreshable sources so cert/key/CA
/// triples with mixed sources notice the fastest configured source. File-backed
/// sources default to the surface's file-watch interval, while provider-backed
/// sources default to `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS`. A URI `?poll=`
/// option overrides the default for that specific source.
pub fn material_set_poll_interval(
    sources: &[WatchedMaterialSource],
    file_default: Duration,
    provider_default: Duration,
) -> Duration {
    let file_default = clamp_poll_interval(file_default);
    let provider_default = clamp_poll_interval(provider_default);
    sources
        .iter()
        .filter_map(|source| source_poll_interval(&source.source, file_default, provider_default))
        .min()
        .unwrap_or(file_default)
}

fn source_poll_interval(
    source: &CertSource,
    file_default: Duration,
    provider_default: Duration,
) -> Option<Duration> {
    match source {
        CertSource::Path(_) => Some(file_default),
        CertSource::InlinePem(_) => None,
        CertSource::Uri(uri) => {
            if !source_is_refreshable(source) {
                return None;
            }
            let default = match uri.scheme {
                SourceScheme::File => file_default,
                _ => provider_default,
            };
            let Some(raw) = uri
                .options
                .get("poll")
                .or_else(|| uri.options.get("poll_interval"))
                .or_else(|| uri.options.get("poll_interval_seconds"))
            else {
                return Some(default);
            };
            match parse_poll_interval(raw) {
                Ok(interval) => Some(interval),
                Err(details) => {
                    warn!(
                        source_id = %uri.source_id(),
                        poll = %raw,
                        details = %details,
                        "Invalid TLS material source poll interval; using default"
                    );
                    Some(default)
                }
            }
        }
    }
}

fn parse_poll_interval(raw: &str) -> Result<Duration, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty interval");
    }

    let (number, multiplier) = if let Some(value) = trimmed.strip_suffix('s') {
        (value, 1_u64)
    } else if let Some(value) = trimmed.strip_suffix('m') {
        (value, 60_u64)
    } else if let Some(value) = trimmed.strip_suffix('h') {
        (value, 3_600_u64)
    } else if let Some(value) = trimmed.strip_suffix('d') {
        (value, 86_400_u64)
    } else {
        (trimmed, 1_u64)
    };

    let seconds = number
        .parse::<u64>()
        .map_err(|_| "expected a positive integer with optional s/m/h/d suffix")?
        .checked_mul(multiplier)
        .ok_or("interval overflow")?;
    Ok(clamp_poll_interval(Duration::from_secs(seconds)))
}

fn clamp_poll_interval(interval: Duration) -> Duration {
    let secs = interval.as_secs().clamp(1, MAX_SOURCE_POLL_INTERVAL_SECS);
    Duration::from_secs(secs)
}

/// Fingerprint all configured sources using their material bytes.
pub fn material_set_fingerprint(
    sources: &[WatchedMaterialSource],
) -> Result<MaterialSetFingerprint, MaterialError> {
    let mut entries = Vec::with_capacity(sources.len());
    for watched in sources {
        if let Some(entry) = opaque_key_fingerprint_entry(watched) {
            entries.push(entry);
            continue;
        }
        let configured_scheme = configured_source_scheme(&watched.source);
        let started = Instant::now();
        let material = match load_material_blocking(&watched.source, watched.kind) {
            Ok(material) => material,
            Err(error) => {
                let registry = crate::plugins::prometheus_metrics::global_registry();
                registry.record_tls_source_fetch_duration(
                    configured_scheme.as_str(),
                    watched.kind.as_str(),
                    started.elapsed().as_secs_f64(),
                );
                registry.record_tls_source_fetch_failure(
                    configured_scheme.as_str(),
                    watched.kind.as_str(),
                    material_error_reason(&error),
                );
                return Err(error);
            }
        };
        crate::plugins::prometheus_metrics::global_registry().record_tls_source_fetch_duration(
            material.source_kind.as_str(),
            material.kind.as_str(),
            started.elapsed().as_secs_f64(),
        );
        entries.push(MaterialFingerprintEntry {
            label: watched.label,
            source_id: material.source_id,
            fingerprint: material.fingerprint,
            version: material.version,
            source_kind: material.source_kind,
            kind: material.kind,
        });
    }
    Ok(MaterialSetFingerprint { entries })
}

fn opaque_key_fingerprint_entry(
    watched: &WatchedMaterialSource,
) -> Option<MaterialFingerprintEntry> {
    let CertSource::Uri(uri) = &watched.source else {
        return None;
    };
    if uri.scheme != SourceScheme::Pkcs11 || watched.kind != MaterialKind::Key {
        return None;
    }
    let digest = Sha256::digest(watched.source.to_config_value().as_bytes());
    let mut fingerprint = [0_u8; 32];
    fingerprint.copy_from_slice(&digest);
    Some(MaterialFingerprintEntry {
        label: watched.label,
        source_id: uri.source_id(),
        fingerprint,
        version: None,
        source_kind: SourceScheme::Pkcs11,
        kind: watched.kind,
    })
}

fn material_error_reason(error: &MaterialError) -> &'static str {
    match error {
        MaterialError::Io { .. } => "io",
        MaterialError::UnsupportedScheme { .. } => "unsupported_scheme",
        MaterialError::Secret { .. } => "secret",
        MaterialError::InvalidSource { .. } => "invalid_source",
    }
}

/// Surface-specific rebuild closure run after a source-set fingerprint changes.
pub type MaterialSetRebuildFn = Box<dyn Fn() -> Result<(), anyhow::Error> + Send + Sync + 'static>;
pub type MaterialSetAsyncRebuildFn =
    Box<dyn Fn() -> BoxFuture<'static, Result<(), anyhow::Error>> + Send + Sync + 'static>;

/// Configuration for [`spawn_material_set_reload_task`].
pub struct MaterialSetReloadConfig {
    pub surface: &'static str,
    pub sources: Vec<WatchedMaterialSource>,
    pub interval: Duration,
    pub revision_tx: watch::Sender<u64>,
    pub rebuild: MaterialSetRebuildFn,
}

/// Configuration for [`spawn_async_material_set_reload_task`].
pub struct AsyncMaterialSetReloadConfig {
    pub surface: &'static str,
    pub sources: Vec<WatchedMaterialSource>,
    pub interval: Duration,
    pub revision_tx: watch::Sender<u64>,
    pub rebuild: MaterialSetAsyncRebuildFn,
}

pub type MaterialSetSourceCollectorFn =
    Box<dyn Fn() -> Vec<WatchedMaterialSource> + Send + Sync + 'static>;

/// Configuration for [`spawn_dynamic_material_set_reload_task`].
pub struct DynamicMaterialSetReloadConfig {
    pub surface: &'static str,
    pub collect_sources: MaterialSetSourceCollectorFn,
    pub file_default_interval: Duration,
    pub provider_default_interval: Duration,
    pub revision_tx: watch::Sender<u64>,
    pub rebuild: MaterialSetRebuildFn,
}

/// Spawn a polling reload task for a set of TLS material sources.
pub fn spawn_material_set_reload_task(
    config: MaterialSetReloadConfig,
    shutdown_rx: Option<watch::Receiver<bool>>,
) -> JoinHandle<()> {
    let surface = config.surface;
    let (force_tx, force_rx) = mpsc::channel(1);
    force_reload_registry().insert(surface, force_tx.clone());
    tokio::spawn(async move {
        let k8s_watchers = spawn_k8s_secret_watchers(
            surface,
            &config.sources,
            Some(force_tx),
            shutdown_rx.clone(),
        );
        run_material_set_reload_loop(config, shutdown_rx, force_rx).await;
        for handle in k8s_watchers {
            handle.abort();
        }
    })
}

/// Spawn a polling reload task for a source set with an async rebuild step.
pub fn spawn_async_material_set_reload_task(
    config: AsyncMaterialSetReloadConfig,
    shutdown_rx: Option<watch::Receiver<bool>>,
) -> JoinHandle<()> {
    let surface = config.surface;
    let (force_tx, force_rx) = mpsc::channel(1);
    force_reload_registry().insert(surface, force_tx.clone());
    tokio::spawn(async move {
        let k8s_watchers = spawn_k8s_secret_watchers(
            surface,
            &config.sources,
            Some(force_tx),
            shutdown_rx.clone(),
        );
        run_async_material_set_reload_loop(config, shutdown_rx, force_rx).await;
        for handle in k8s_watchers {
            handle.abort();
        }
    })
}

/// Spawn a polling reload task whose source set is collected on each iteration.
///
/// This is for surfaces whose owning runtime can atomically swap config while
/// the process keeps running. It preserves the same byte-fingerprint rotation
/// predicate as [`spawn_material_set_reload_task`], but refreshes Kubernetes
/// watches and polling intervals whenever the configured source set changes.
pub fn spawn_dynamic_material_set_reload_task(
    config: DynamicMaterialSetReloadConfig,
    shutdown_rx: Option<watch::Receiver<bool>>,
) -> JoinHandle<()> {
    let surface = config.surface;
    let (force_tx, force_rx) = mpsc::channel(1);
    force_reload_registry().insert(surface, force_tx.clone());
    tokio::spawn(async move {
        run_dynamic_material_set_reload_loop(config, shutdown_rx, force_rx, force_tx).await;
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct K8sSecretWatcherTarget {
    namespace: String,
    name: String,
    source_ids: Vec<String>,
}

fn k8s_secret_watcher_targets(sources: &[WatchedMaterialSource]) -> Vec<K8sSecretWatcherTarget> {
    let mut grouped = BTreeMap::<(String, String), BTreeSet<String>>::new();
    for source in sources {
        let Some(target) = k8s_secret_watch_target(&source.source, source.kind) else {
            continue;
        };
        match target {
            Ok(target) => {
                grouped
                    .entry((target.namespace, target.name))
                    .or_default()
                    .insert(target.source_id);
            }
            Err(error) => {
                warn!(
                    error = %error,
                    "Skipping Kubernetes Secret watch registration for invalid TLS source"
                );
            }
        }
    }
    grouped
        .into_iter()
        .map(|((namespace, name), source_ids)| K8sSecretWatcherTarget {
            namespace,
            name,
            source_ids: source_ids.into_iter().collect(),
        })
        .collect()
}

fn spawn_k8s_secret_watchers(
    surface: &'static str,
    sources: &[WatchedMaterialSource],
    force_tx: Option<mpsc::Sender<()>>,
    shutdown_rx: Option<watch::Receiver<bool>>,
) -> Vec<JoinHandle<()>> {
    let Some(force_tx) = force_tx else {
        return Vec::new();
    };
    k8s_secret_watcher_targets(sources)
        .into_iter()
        .map(|target| {
            tokio::spawn(run_k8s_secret_watch(
                surface,
                target,
                force_tx.clone(),
                shutdown_rx.clone(),
            ))
        })
        .collect()
}

async fn run_k8s_secret_watch(
    surface: &'static str,
    target: K8sSecretWatcherTarget,
    force_tx: mpsc::Sender<()>,
    mut shutdown_rx: Option<watch::Receiver<bool>>,
) {
    let client = match kube::Client::try_default().await {
        Ok(client) => client,
        Err(error) => {
            warn!(
                surface,
                namespace = %target.namespace,
                secret = %target.name,
                error = %error,
                "Kubernetes Secret watch could not create a client; TLS source polling remains active"
            );
            return;
        }
    };
    let secrets: kube::Api<k8s_openapi::api::core::v1::Secret> =
        kube::Api::namespaced(client, &target.namespace);
    let field_selector = format!("metadata.name={}", target.name);
    let stream = kube::runtime::watcher::watcher(
        secrets,
        kube::runtime::watcher::Config::default().fields(&field_selector),
    );
    tokio::pin!(stream);
    let mut initialized = false;

    info!(
        surface,
        namespace = %target.namespace,
        secret = %target.name,
        source_count = target.source_ids.len(),
        "Kubernetes Secret TLS source watcher started"
    );

    loop {
        let item = if let Some(shutdown) = shutdown_rx.as_mut() {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        debug!(
                            surface,
                            namespace = %target.namespace,
                            secret = %target.name,
                            "Kubernetes Secret TLS source watcher shutting down"
                        );
                        return;
                    }
                    continue;
                }
                item = stream.try_next() => item,
            }
        } else {
            stream.try_next().await
        };

        match item {
            Ok(Some(event)) => match event {
                kube::runtime::watcher::Event::Init => {
                    initialized = false;
                }
                kube::runtime::watcher::Event::InitApply(_) => {}
                kube::runtime::watcher::Event::InitDone => {
                    initialized = true;
                }
                kube::runtime::watcher::Event::Apply(_)
                | kube::runtime::watcher::Event::Delete(_) => {
                    if initialized {
                        match force_tx.try_send(()) {
                            Ok(()) | Err(TrySendError::Full(_)) => {
                                info!(
                                    surface,
                                    namespace = %target.namespace,
                                    secret = %target.name,
                                    "Kubernetes Secret changed; queued TLS source reload"
                                );
                            }
                            Err(TrySendError::Closed(_)) => return,
                        }
                    }
                }
            },
            Ok(None) => {
                warn!(
                    surface,
                    namespace = %target.namespace,
                    secret = %target.name,
                    "Kubernetes Secret TLS source watcher stream ended; source polling remains active"
                );
                return;
            }
            Err(error) => {
                warn!(
                    surface,
                    namespace = %target.namespace,
                    secret = %target.name,
                    error = %error,
                    "Kubernetes Secret watch error; kube-rs will retry and TLS source polling remains active"
                );
            }
        }
    }
}

async fn run_material_set_reload_loop(
    config: MaterialSetReloadConfig,
    mut shutdown_rx: Option<watch::Receiver<bool>>,
    mut force_rx: mpsc::Receiver<()>,
) {
    let MaterialSetReloadConfig {
        surface,
        sources,
        interval,
        revision_tx,
        rebuild,
    } = config;

    if sources.is_empty() {
        info!(
            surface,
            "TLS material reload watcher has no sources; exiting"
        );
        force_reload_registry().remove(surface);
        return;
    }

    info!(
        surface,
        source_count = sources.len(),
        interval_secs = interval.as_secs(),
        "TLS material source reload watcher started"
    );

    let mut last_fingerprint = match material_set_fingerprint(&sources) {
        Ok(fingerprint) => Some(fingerprint),
        Err(error) => {
            record_refresh_for_sources(surface, &sources, "load_error");
            crate::tls::events::record_load_error(surface, &sources, &error.to_string());
            warn!(
                surface,
                error = %error,
                "TLS material source watcher could not read startup fingerprint; continuing and will retry"
            );
            None
        }
    };
    let mut last_load_failed = last_fingerprint.is_none();

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if shutdown_rx.as_ref().is_some_and(|rx| *rx.borrow()) {
            force_reload_registry().remove(surface);
            return;
        }

        if let Some(shutdown) = shutdown_rx.as_mut() {
            tokio::select! {
                _ = ticker.tick() => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        force_reload_registry().remove(surface);
                        return;
                    }
                    continue;
                }
                forced = force_rx.recv() => {
                    if forced.is_none() {
                        force_reload_registry().remove(surface);
                        return;
                    }
                }
            }
        } else {
            tokio::select! {
                _ = ticker.tick() => {}
                forced = force_rx.recv() => {
                    if forced.is_none() {
                        force_reload_registry().remove(surface);
                        return;
                    }
                }
            }
        }

        let next_fingerprint = match material_set_fingerprint(&sources) {
            Ok(fingerprint) => {
                if last_load_failed {
                    info!(
                        surface,
                        "TLS material source watcher recovered source access"
                    );
                    last_load_failed = false;
                }
                fingerprint
            }
            Err(error) => {
                record_refresh_for_sources(surface, &sources, "load_error");
                crate::tls::events::record_load_error(surface, &sources, &error.to_string());
                if !last_load_failed {
                    warn!(
                        surface,
                        error = %error,
                        "TLS material source watcher could not load source bytes; keeping current material (silenced until load succeeds again)"
                    );
                    last_load_failed = true;
                }
                continue;
            }
        };

        if last_fingerprint.as_ref() == Some(&next_fingerprint) {
            record_refresh_for_entries(surface, &next_fingerprint.entries, "unchanged");
            continue;
        }

        match rebuild() {
            Ok(()) => {
                let event_entries = next_fingerprint.entries.clone();
                record_refresh_for_entries(surface, &next_fingerprint.entries, "rotated");
                last_fingerprint = Some(next_fingerprint);
                revision_tx.send_modify(|r| *r = r.saturating_add(1));
                let revision = *revision_tx.borrow();
                crate::tls::events::record_rotation_success(surface, &event_entries, revision);
                info!(
                    surface,
                    revision,
                    "TLS material sources reloaded; new handshakes/connections will use rotated material"
                );
            }
            Err(error) => {
                record_refresh_for_entries(surface, &next_fingerprint.entries, "rebuild_error");
                crate::tls::events::record_rebuild_error(
                    surface,
                    &next_fingerprint.entries,
                    &error,
                );
                last_fingerprint = Some(next_fingerprint);
                warn!(
                    surface,
                    error = %error,
                    "TLS material sources changed but rebuild failed; keeping previous material"
                );
            }
        }
    }
}

async fn run_async_material_set_reload_loop(
    config: AsyncMaterialSetReloadConfig,
    mut shutdown_rx: Option<watch::Receiver<bool>>,
    mut force_rx: mpsc::Receiver<()>,
) {
    let AsyncMaterialSetReloadConfig {
        surface,
        sources,
        interval,
        revision_tx,
        rebuild,
    } = config;

    if sources.is_empty() {
        info!(
            surface,
            "TLS material reload watcher has no sources; exiting"
        );
        force_reload_registry().remove(surface);
        return;
    }

    info!(
        surface,
        source_count = sources.len(),
        interval_secs = interval.as_secs(),
        "TLS material source reload watcher started"
    );

    let mut last_fingerprint = match material_set_fingerprint(&sources) {
        Ok(fingerprint) => Some(fingerprint),
        Err(error) => {
            record_refresh_for_sources(surface, &sources, "load_error");
            crate::tls::events::record_load_error(surface, &sources, &error.to_string());
            warn!(
                surface,
                error = %error,
                "TLS material source watcher could not read startup fingerprint; continuing and will retry"
            );
            None
        }
    };
    let mut last_load_failed = last_fingerprint.is_none();

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if shutdown_rx.as_ref().is_some_and(|rx| *rx.borrow()) {
            force_reload_registry().remove(surface);
            return;
        }

        if let Some(shutdown) = shutdown_rx.as_mut() {
            tokio::select! {
                _ = ticker.tick() => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        force_reload_registry().remove(surface);
                        return;
                    }
                    continue;
                }
                forced = force_rx.recv() => {
                    if forced.is_none() {
                        force_reload_registry().remove(surface);
                        return;
                    }
                }
            }
        } else {
            tokio::select! {
                _ = ticker.tick() => {}
                forced = force_rx.recv() => {
                    if forced.is_none() {
                        force_reload_registry().remove(surface);
                        return;
                    }
                }
            }
        }

        let next_fingerprint = match material_set_fingerprint(&sources) {
            Ok(fingerprint) => {
                if last_load_failed {
                    info!(
                        surface,
                        "TLS material source watcher recovered source access"
                    );
                    last_load_failed = false;
                }
                fingerprint
            }
            Err(error) => {
                record_refresh_for_sources(surface, &sources, "load_error");
                crate::tls::events::record_load_error(surface, &sources, &error.to_string());
                if !last_load_failed {
                    warn!(
                        surface,
                        error = %error,
                        "TLS material source watcher could not load source bytes; keeping current material (silenced until load succeeds again)"
                    );
                    last_load_failed = true;
                }
                continue;
            }
        };

        if last_fingerprint.as_ref() == Some(&next_fingerprint) {
            record_refresh_for_entries(surface, &next_fingerprint.entries, "unchanged");
            continue;
        }

        match rebuild().await {
            Ok(()) => {
                let event_entries = next_fingerprint.entries.clone();
                record_refresh_for_entries(surface, &next_fingerprint.entries, "rotated");
                last_fingerprint = Some(next_fingerprint);
                revision_tx.send_modify(|r| *r = r.saturating_add(1));
                let revision = *revision_tx.borrow();
                crate::tls::events::record_rotation_success(surface, &event_entries, revision);
                info!(
                    surface,
                    revision,
                    "TLS material sources reloaded; new handshakes/connections will use rotated material"
                );
            }
            Err(error) => {
                record_refresh_for_entries(surface, &next_fingerprint.entries, "rebuild_error");
                crate::tls::events::record_rebuild_error(
                    surface,
                    &next_fingerprint.entries,
                    &error,
                );
                last_fingerprint = Some(next_fingerprint);
                warn!(
                    surface,
                    error = %error,
                    "TLS material sources changed but rebuild failed; keeping previous material"
                );
            }
        }
    }
}

async fn run_dynamic_material_set_reload_loop(
    config: DynamicMaterialSetReloadConfig,
    mut shutdown_rx: Option<watch::Receiver<bool>>,
    mut force_rx: mpsc::Receiver<()>,
    force_tx: mpsc::Sender<()>,
) {
    let DynamicMaterialSetReloadConfig {
        surface,
        collect_sources,
        file_default_interval,
        provider_default_interval,
        revision_tx,
        rebuild,
    } = config;

    let mut last_fingerprint: Option<MaterialSetFingerprint> = None;
    let mut last_load_failed = false;
    let mut last_source_signature: Option<Vec<(MaterialKind, String)>> = None;
    let mut k8s_targets = Vec::new();
    let mut k8s_handles = Vec::new();

    loop {
        if shutdown_rx.as_ref().is_some_and(|rx| *rx.borrow()) {
            cleanup_dynamic_reload(surface, &mut k8s_handles);
            return;
        }

        let sources = collect_sources();
        refresh_dynamic_k8s_watchers(
            surface,
            &sources,
            &force_tx,
            shutdown_rx.clone(),
            &mut k8s_targets,
            &mut k8s_handles,
        );

        let source_signature = watched_source_signature(&sources);
        if last_source_signature.as_ref() != Some(&source_signature) {
            info!(
                surface,
                source_count = sources.len(),
                "TLS material source set changed; refreshed dynamic watcher inputs"
            );
            last_source_signature = Some(source_signature);
            last_fingerprint = None;
            last_load_failed = false;
        }

        let interval =
            material_set_poll_interval(&sources, file_default_interval, provider_default_interval);

        if sources.is_empty() {
            if !wait_material_set_reload_tick(interval, &mut shutdown_rx, &mut force_rx).await {
                cleanup_dynamic_reload(surface, &mut k8s_handles);
                return;
            }
            continue;
        }

        let next_fingerprint = match material_set_fingerprint(&sources) {
            Ok(fingerprint) => {
                if last_load_failed {
                    info!(
                        surface,
                        "TLS material source watcher recovered source access"
                    );
                    last_load_failed = false;
                }
                fingerprint
            }
            Err(error) => {
                record_refresh_for_sources(surface, &sources, "load_error");
                crate::tls::events::record_load_error(surface, &sources, &error.to_string());
                if !last_load_failed {
                    warn!(
                        surface,
                        error = %error,
                        "TLS material source watcher could not load source bytes; keeping current material (silenced until load succeeds again)"
                    );
                    last_load_failed = true;
                }
                if !wait_material_set_reload_tick(interval, &mut shutdown_rx, &mut force_rx).await {
                    cleanup_dynamic_reload(surface, &mut k8s_handles);
                    return;
                }
                continue;
            }
        };

        if last_fingerprint.is_none() {
            last_fingerprint = Some(next_fingerprint);
            if !wait_material_set_reload_tick(interval, &mut shutdown_rx, &mut force_rx).await {
                cleanup_dynamic_reload(surface, &mut k8s_handles);
                return;
            }
            continue;
        }

        if last_fingerprint.as_ref() == Some(&next_fingerprint) {
            record_refresh_for_entries(surface, &next_fingerprint.entries, "unchanged");
            if !wait_material_set_reload_tick(interval, &mut shutdown_rx, &mut force_rx).await {
                cleanup_dynamic_reload(surface, &mut k8s_handles);
                return;
            }
            continue;
        }

        match rebuild() {
            Ok(()) => {
                let event_entries = next_fingerprint.entries.clone();
                record_refresh_for_entries(surface, &next_fingerprint.entries, "rotated");
                last_fingerprint = Some(next_fingerprint);
                revision_tx.send_modify(|r| *r = r.saturating_add(1));
                let revision = *revision_tx.borrow();
                crate::tls::events::record_rotation_success(surface, &event_entries, revision);
                info!(
                    surface,
                    revision,
                    "TLS material sources reloaded; new handshakes/connections will use rotated material"
                );
            }
            Err(error) => {
                record_refresh_for_entries(surface, &next_fingerprint.entries, "rebuild_error");
                crate::tls::events::record_rebuild_error(
                    surface,
                    &next_fingerprint.entries,
                    &error,
                );
                last_fingerprint = Some(next_fingerprint);
                warn!(
                    surface,
                    error = %error,
                    "TLS material sources changed but rebuild failed; keeping previous material"
                );
            }
        }

        if !wait_material_set_reload_tick(interval, &mut shutdown_rx, &mut force_rx).await {
            cleanup_dynamic_reload(surface, &mut k8s_handles);
            return;
        }
    }
}

fn watched_source_signature(sources: &[WatchedMaterialSource]) -> Vec<(MaterialKind, String)> {
    let mut signature = sources
        .iter()
        .map(|source| (source.kind, source.source.pool_key_component()))
        .collect::<Vec<_>>();
    signature.sort();
    signature
}

fn refresh_dynamic_k8s_watchers(
    surface: &'static str,
    sources: &[WatchedMaterialSource],
    force_tx: &mpsc::Sender<()>,
    shutdown_rx: Option<watch::Receiver<bool>>,
    current_targets: &mut Vec<K8sSecretWatcherTarget>,
    handles: &mut Vec<JoinHandle<()>>,
) {
    let next_targets = k8s_secret_watcher_targets(sources);
    if *current_targets == next_targets {
        return;
    }
    abort_k8s_watchers(handles);
    *current_targets = next_targets;
    if current_targets.is_empty() {
        return;
    }
    *handles = spawn_k8s_secret_watchers(surface, sources, Some(force_tx.clone()), shutdown_rx);
}

fn abort_k8s_watchers(handles: &mut Vec<JoinHandle<()>>) {
    for handle in handles.drain(..) {
        handle.abort();
    }
}

fn cleanup_dynamic_reload(surface: &'static str, k8s_handles: &mut Vec<JoinHandle<()>>) {
    abort_k8s_watchers(k8s_handles);
    force_reload_registry().remove(surface);
}

async fn wait_material_set_reload_tick(
    interval: Duration,
    shutdown_rx: &mut Option<watch::Receiver<bool>>,
    force_rx: &mut mpsc::Receiver<()>,
) -> bool {
    let sleep = tokio::time::sleep(interval);
    tokio::pin!(sleep);

    if let Some(shutdown) = shutdown_rx.as_mut() {
        tokio::select! {
            _ = &mut sleep => true,
            changed = shutdown.changed() => changed.is_ok() && !*shutdown.borrow(),
            forced = force_rx.recv() => forced.is_some(),
        }
    } else {
        tokio::select! {
            _ = &mut sleep => true,
            forced = force_rx.recv() => forced.is_some(),
        }
    }
}

fn record_refresh_for_entries(
    surface: &'static str,
    entries: &[MaterialFingerprintEntry],
    outcome: &'static str,
) {
    let registry = crate::plugins::prometheus_metrics::global_registry();
    for entry in entries {
        registry.record_tls_source_refresh(
            entry.source_kind.as_str(),
            entry.kind.as_str(),
            surface,
            outcome,
        );
    }
}

fn record_refresh_for_sources(
    surface: &'static str,
    sources: &[WatchedMaterialSource],
    outcome: &'static str,
) {
    let registry = crate::plugins::prometheus_metrics::global_registry();
    for source in sources {
        registry.record_tls_source_refresh(
            configured_source_scheme(&source.source).as_str(),
            source.kind.as_str(),
            surface,
            outcome,
        );
    }
}

fn configured_source_scheme(source: &CertSource) -> SourceScheme {
    match source {
        CertSource::Path(_) | CertSource::InlinePem(_) => SourceScheme::File,
        CertSource::Uri(uri) => uri.scheme,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn source_fingerprint_ignores_same_byte_rewrites() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cert.pem");
        std::fs::write(&path, b"same bytes").expect("write");
        let source = CertSource::parse(path.to_string_lossy().into_owned(), MaterialKind::Cert);
        let watched = vec![WatchedMaterialSource::new(
            "cert",
            source,
            MaterialKind::Cert,
        )];

        let first = material_set_fingerprint(&watched).expect("first fingerprint");
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&path, b"same bytes").expect("rewrite");
        let second = material_set_fingerprint(&watched).expect("second fingerprint");

        assert_eq!(first, second);
    }

    #[test]
    fn source_fingerprint_changes_when_bytes_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cert.pem");
        std::fs::write(&path, b"first bytes").expect("write");
        let source = CertSource::parse(path.to_string_lossy().into_owned(), MaterialKind::Cert);
        let watched = vec![WatchedMaterialSource::new(
            "cert",
            source,
            MaterialKind::Cert,
        )];

        let first = material_set_fingerprint(&watched).expect("first fingerprint");
        std::fs::write(&path, b"second bytes").expect("rewrite");
        let second = material_set_fingerprint(&watched).expect("second fingerprint");

        assert_ne!(first, second);
    }

    #[test]
    fn inline_sources_are_not_refreshable() {
        let source = CertSource::parse(
            "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n",
            MaterialKind::Cert,
        );
        assert!(!source_is_refreshable(&source));
    }

    #[test]
    fn pkcs11_key_sources_use_stable_opaque_fingerprint() {
        let source = CertSource::parse(
            "pkcs11://edge-rsa?module=/usr/lib/pkcs11.so&pin_env=FERRUM_PKCS11_PIN",
            MaterialKind::Key,
        );
        let watched = vec![WatchedMaterialSource::new("key", source, MaterialKind::Key)];

        let first = material_set_fingerprint(&watched).expect("first fingerprint");
        let second = material_set_fingerprint(&watched).expect("second fingerprint");

        assert_eq!(first, second);
        assert_eq!(first.entries.len(), 1);
        assert_eq!(first.entries[0].source_kind, SourceScheme::Pkcs11);
        assert_eq!(first.entries[0].kind, MaterialKind::Key);
    }

    #[test]
    fn material_set_poll_interval_uses_file_default_for_file_sources() {
        let source = CertSource::parse("/tmp/cert.pem", MaterialKind::Cert);
        let watched = vec![WatchedMaterialSource::new(
            "cert",
            source,
            MaterialKind::Cert,
        )];

        assert_eq!(
            material_set_poll_interval(&watched, Duration::from_secs(30), Duration::from_secs(300),),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn material_set_poll_interval_uses_provider_default_for_provider_sources() {
        let source = CertSource::parse("vault://secret/data/edge#cert", MaterialKind::Cert);
        let watched = vec![WatchedMaterialSource::new(
            "cert",
            source,
            MaterialKind::Cert,
        )];

        assert_eq!(
            material_set_poll_interval(&watched, Duration::from_secs(30), Duration::from_secs(300),),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn material_set_poll_interval_prefers_source_poll_option() {
        let source = CertSource::parse("vault://secret/data/edge#cert?poll=2m", MaterialKind::Cert);
        let watched = vec![WatchedMaterialSource::new(
            "cert",
            source,
            MaterialKind::Cert,
        )];

        assert_eq!(
            material_set_poll_interval(&watched, Duration::from_secs(30), Duration::from_secs(300),),
            Duration::from_secs(120)
        );
    }

    #[test]
    fn material_set_poll_interval_uses_fastest_refreshable_source() {
        let file = CertSource::parse("/tmp/cert.pem", MaterialKind::Cert);
        let provider = CertSource::parse("aws://edge/key?poll=10s", MaterialKind::Key);
        let inline = CertSource::parse(
            "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n",
            MaterialKind::Cert,
        );
        let watched = vec![
            WatchedMaterialSource::new("cert", file, MaterialKind::Cert),
            WatchedMaterialSource::new("key", provider, MaterialKind::Key),
            WatchedMaterialSource::new("chain", inline, MaterialKind::Cert),
        ];

        assert_eq!(
            material_set_poll_interval(&watched, Duration::from_secs(30), Duration::from_secs(300),),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn k8s_secret_watcher_targets_deduplicate_secret_sources() {
        let cert = CertSource::parse("k8s://edge/frontend#tls.crt", MaterialKind::Cert);
        let key = CertSource::parse("k8s://edge/frontend#tls.key", MaterialKind::Key);
        let other = CertSource::parse("k8s://edge/admin#tls.crt", MaterialKind::Cert);
        let file = CertSource::parse("/tmp/local.pem", MaterialKind::Cert);
        let watched = vec![
            WatchedMaterialSource::new("cert", cert, MaterialKind::Cert),
            WatchedMaterialSource::new("key", key, MaterialKind::Key),
            WatchedMaterialSource::new("admin", other, MaterialKind::Cert),
            WatchedMaterialSource::new("file", file, MaterialKind::Cert),
        ];

        let targets = k8s_secret_watcher_targets(&watched);

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].namespace, "edge");
        assert_eq!(targets[0].name, "admin");
        assert_eq!(targets[0].source_ids, vec!["k8s://edge/admin#tls.crt"]);
        assert_eq!(targets[1].namespace, "edge");
        assert_eq!(targets[1].name, "frontend");
        assert_eq!(targets[1].source_ids.len(), 2);
        assert!(
            targets[1]
                .source_ids
                .contains(&"k8s://edge/frontend#tls.crt".to_string())
        );
        assert!(
            targets[1]
                .source_ids
                .contains(&"k8s://edge/frontend#tls.key".to_string())
        );
    }

    #[tokio::test]
    async fn reload_task_bumps_only_on_changed_bytes_and_successful_rebuild() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cert.pem");
        std::fs::write(&path, b"first bytes").expect("write");
        let source = CertSource::parse(path.to_string_lossy().into_owned(), MaterialKind::Cert);

        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();
        let rebuild: MaterialSetRebuildFn = Box::new(move || {
            let attempt = attempts_clone.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                Ok(())
            } else {
                Err(anyhow::anyhow!("simulated rebuild failure"))
            }
        });

        let (revision_tx, mut revision_rx) = watch::channel(0u64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = spawn_material_set_reload_task(
            MaterialSetReloadConfig {
                // Unique surface per test: the force-reload registry is a
                // process-global keyed by surface, so a shared name lets a
                // parallel test's task drop this one's force sender and exit
                // early (`cargo test --lib` runs tests concurrently).
                surface: "test_material_set_bump",
                sources: vec![WatchedMaterialSource::new(
                    "cert",
                    source,
                    MaterialKind::Cert,
                )],
                interval: Duration::from_millis(50),
                revision_tx,
                rebuild,
            },
            Some(shutdown_rx),
        );

        tokio::time::sleep(Duration::from_millis(80)).await;
        std::fs::write(&path, b"same bytes as next").expect("rewrite changed bytes");
        tokio::time::timeout(Duration::from_secs(2), revision_rx.changed())
            .await
            .expect("revision should bump")
            .expect("watcher should still be alive");
        assert_eq!(*revision_rx.borrow(), 1);

        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&path, b"same bytes as next").expect("rewrite same bytes");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            *revision_rx.borrow(),
            1,
            "same bytes must not bump revision"
        );

        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&path, b"different failing bytes").expect("rewrite changed bytes");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            *revision_rx.borrow(),
            1,
            "failed rebuild must not bump revision"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        shutdown_tx.send_replace(true);
        task.await.expect("watcher exits cleanly");
    }

    #[tokio::test]
    async fn force_reload_request_triggers_immediate_poll() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cert.pem");
        std::fs::write(&path, b"first bytes").expect("write");
        let source = CertSource::parse(path.to_string_lossy().into_owned(), MaterialKind::Cert);

        let rebuild: MaterialSetRebuildFn = Box::new(|| Ok(()));
        let (revision_tx, mut revision_rx) = watch::channel(0u64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = spawn_material_set_reload_task(
            MaterialSetReloadConfig {
                surface: "test_force_reload",
                sources: vec![WatchedMaterialSource::new(
                    "cert",
                    source,
                    MaterialKind::Cert,
                )],
                interval: Duration::from_secs(3600),
                revision_tx,
                rebuild,
            },
            Some(shutdown_rx),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        std::fs::write(&path, b"second bytes").expect("rewrite changed bytes");

        assert!(request_material_set_reload("test_force_reload"));
        tokio::time::timeout(Duration::from_secs(2), revision_rx.changed())
            .await
            .expect("force reload should bump revision")
            .expect("watcher should still be alive");
        assert_eq!(*revision_rx.borrow(), 1);

        shutdown_tx.send_replace(true);
        task.await.expect("watcher exits cleanly");
    }

    #[tokio::test]
    async fn async_reload_task_awaits_rebuild_before_revision_bump() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cert.pem");
        std::fs::write(&path, b"first bytes").expect("write");
        let source = CertSource::parse(path.to_string_lossy().into_owned(), MaterialKind::Cert);

        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();
        let rebuild: MaterialSetAsyncRebuildFn = Box::new(move || {
            let attempts_clone = attempts_clone.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(25)).await;
                attempts_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        let (revision_tx, mut revision_rx) = watch::channel(0u64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = spawn_async_material_set_reload_task(
            AsyncMaterialSetReloadConfig {
                surface: "test_async_reload",
                sources: vec![WatchedMaterialSource::new(
                    "cert",
                    source,
                    MaterialKind::Cert,
                )],
                interval: Duration::from_secs(3600),
                revision_tx,
                rebuild,
            },
            Some(shutdown_rx),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        std::fs::write(&path, b"second bytes").expect("rewrite changed bytes");

        assert!(request_material_set_reload("test_async_reload"));
        tokio::time::timeout(Duration::from_secs(2), revision_rx.changed())
            .await
            .expect("async rebuild should bump revision")
            .expect("watcher should still be alive");
        assert_eq!(*revision_rx.borrow(), 1);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        shutdown_tx.send_replace(true);
        task.await.expect("watcher exits cleanly");
    }

    #[tokio::test]
    async fn dynamic_reload_task_tracks_source_set_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first_path = dir.path().join("first.pem");
        let second_path = dir.path().join("second.pem");
        std::fs::write(&first_path, b"first bytes").expect("write first");
        std::fs::write(&second_path, b"second bytes").expect("write second");

        let first_source = CertSource::parse(
            first_path.to_string_lossy().into_owned(),
            MaterialKind::Cert,
        );
        let second_source = CertSource::parse(
            second_path.to_string_lossy().into_owned(),
            MaterialKind::Cert,
        );

        let sources = Arc::new(Mutex::new(vec![WatchedMaterialSource::new(
            "cert",
            first_source,
            MaterialKind::Cert,
        )]));
        let sources_for_collector = sources.clone();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_rebuild = attempts.clone();

        let (revision_tx, mut revision_rx) = watch::channel(0u64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = spawn_dynamic_material_set_reload_task(
            DynamicMaterialSetReloadConfig {
                surface: "test_dynamic_reload",
                collect_sources: Box::new(move || {
                    sources_for_collector.lock().expect("sources lock").clone()
                }),
                file_default_interval: Duration::from_secs(3600),
                provider_default_interval: Duration::from_secs(3600),
                revision_tx,
                rebuild: Box::new(move || {
                    attempts_for_rebuild.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }),
            },
            Some(shutdown_rx),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        std::fs::write(&first_path, b"first rotated").expect("rewrite first");
        assert!(request_material_set_reload("test_dynamic_reload"));
        tokio::time::timeout(Duration::from_secs(2), revision_rx.changed())
            .await
            .expect("first source change should bump revision")
            .expect("watcher should still be alive");
        assert_eq!(*revision_rx.borrow(), 1);

        {
            let mut guard = sources.lock().expect("sources lock");
            *guard = vec![WatchedMaterialSource::new(
                "cert",
                second_source,
                MaterialKind::Cert,
            )];
        }
        assert!(request_material_set_reload("test_dynamic_reload"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            *revision_rx.borrow(),
            1,
            "switching the watched source set establishes a new baseline"
        );

        std::fs::write(&second_path, b"second rotated").expect("rewrite second");
        assert!(request_material_set_reload("test_dynamic_reload"));
        tokio::time::timeout(Duration::from_secs(2), revision_rx.changed())
            .await
            .expect("new source change should bump revision")
            .expect("watcher should still be alive");
        assert_eq!(*revision_rx.borrow(), 2);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        shutdown_tx.send_replace(true);
        task.await.expect("watcher exits cleanly");
    }
}
