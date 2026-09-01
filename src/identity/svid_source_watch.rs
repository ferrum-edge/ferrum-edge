//! Gateway SVID source refresh.
//!
//! The gateway's X.509-SVID is configured as three independent material
//! sources (`FERRUM_GATEWAY_SVID_CERT_*`, `..._KEY_*`, `..._TRUST_BUNDLE_*`),
//! each of which may be a filesystem path, a `file://` URI, inline PEM, or a
//! typed provider URI (`vault://`, `aws://`, `azure://`, `gcp://`, `k8s://`,
//! `acme://`, `managed://`). Provider-issued SVIDs are short-lived by design,
//! so this watcher re-fetches every refreshable source and republishes the
//! bundle when its material bytes (or configured source identity / kind /
//! scheme) change — the same *intent* as the frontend/admin, backend, and
//! database TLS watchers. The gateway SVID rotation predicate deliberately
//! ignores provider-returned `version` metadata: a `k8s://` Secret
//! `resourceVersion` bump, or an ACME/Azure/managed version id for identical
//! bytes, must not churn the SVID slot or backend pools.
//!
//! Three properties are load-bearing and must survive any refactor:
//!
//! 1. **Generations never mix.** A change on any one source triggers one
//!    reload of *all three* through
//!    [`crate::identity::file_loader::load_svid_bundle_from_sources`], which
//!    re-reads cert, key, and trust bundle together and refuses a chain whose
//!    leaf does not match the key. A torn write (new cert, old key) is a
//!    refusal, not a published half-generation.
//! 2. **Last-good survives transient failure.** A source that cannot be read,
//!    or a bundle that fails validation, leaves the live SVID slot untouched
//!    and does not advance the backend SVID generation. The *retry* runs on
//!    every source cadence, but the warning and the [`crate::tls::events`]
//!    record are armed once per distinct failing state — see
//!    [`FailureReporter`], which exists because that event log rewrites its
//!    whole bounded on-disk ring on every record.
//! 3. **The comparison baseline is anchored to startup, not to the first
//!    poll.** [`GatewaySvidSourceTracker::prime`] runs synchronously before the
//!    initial bundle load; baselining lazily inside the spawned task would
//!    adopt whatever the sources hold once the runtime first schedules it and
//!    silently swallow every change made during startup. A prime that could
//!    *not* read every source establishes no baseline, so it latches a forced
//!    first publish instead: the first later complete fingerprint set goes
//!    through the coherent reload-and-publish path rather than being adopted as
//!    a silent baseline, because the live slot may already hold material a
//!    recovered source has since superseded.
//! 4. **The generation boundary advances only after a valid replacement.** The
//!    caller-supplied publish closure installs the bundle *then* bumps
//!    `backend_svid_rotation_tx`, so backend pool keys (`|svidg=<n>`), pool
//!    drains, and health-probe restarts all observe one coherent update — the
//!    identical pipeline file rotation and `POST /admin/tls/rotate/svid` use.
//!
//! Unlike the single-cadence [`crate::tls::source::subscription`] loops, each
//! source here keeps its own due time: a file source is re-read on the
//! gateway's 1s file cadence while a `vault://` source alongside it is fetched
//! only every `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS` (or its own `?poll=`).
//! Collapsing the set onto the fastest member would poll a secret manager once
//! per second. Inline PEM is static until config reload, matching every other
//! TLS surface.

use std::time::{Duration, Instant};

use tokio::sync::watch;
use tracing::{info, warn};

use crate::identity::SvidBundle;
use crate::tls::events::{record_load_error, record_rebuild_error, record_rotation_success};
use crate::tls::source::subscription::{
    MaterialFingerprintEntry, WatchedMaterialSource, material_fingerprint,
    material_fingerprint_async, record_refresh_for_entries, source_poll_interval,
};
use crate::tls::source::{CertSource, MaterialKind, SourceScheme};
use crate::tls::spiffe::SpiffeTlsError;

/// Watch surface name used for TLS source metrics and the TLS event log.
pub const GATEWAY_SVID_SURFACE: &str = "gateway_svid";

/// Default re-read cadence for file-backed gateway SVID sources. This is the
/// historical gateway SVID file-watch interval and is deliberately faster than
/// the frontend/backend file watchers: a SPIFFE Helper rewrite should be picked
/// up promptly, and a local read is cheap.
pub const GATEWAY_SVID_FILE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Upper bound on how long the watcher sleeps between wake-ups. A scheduling
/// bound only: a source is still fetched on its own configured cadence.
const MAX_WATCH_SLEEP: Duration = Duration::from_secs(60);

const CERT_LABEL: &str = "gateway_svid_cert";
const KEY_LABEL: &str = "gateway_svid_key";
const TRUST_BUNDLE_LABEL: &str = "gateway_svid_trust_bundle";

/// Gateway SVID rotation equality for one fingerprint entry.
///
/// Compares configured source identity (`label`, `source_id`), material bytes
/// (`fingerprint`), and the stable role/scheme fields (`kind`, `source_kind`).
/// Provider-returned [`MaterialFingerprintEntry::version`] is observability
/// metadata only — a `k8s://` `resourceVersion` bump (or ACME/Azure/managed
/// version id) for identical bytes must not count as a rotation.
fn gateway_svid_entry_rotation_equivalent(
    left: &MaterialFingerprintEntry,
    right: &MaterialFingerprintEntry,
) -> bool {
    left.label == right.label
        && left.source_id == right.source_id
        && left.fingerprint == right.fingerprint
        && left.source_kind == right.source_kind
        && left.kind == right.kind
}

/// Gateway SVID rotation equality for a complete cert/key/trust-bundle set.
///
/// Used by [`GatewaySvidSourceTracker::poll`] (and the rebuild failure latch)
/// instead of derived [`PartialEq`] on [`MaterialFingerprintEntry`], which
/// includes `version`.
pub fn gateway_svid_rotation_equivalent(
    left: &[MaterialFingerprintEntry],
    right: &[MaterialFingerprintEntry],
) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(a, b)| gateway_svid_entry_rotation_equivalent(a, b))
}

/// How often one configured gateway SVID source is re-read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewaySvidCadence {
    /// Inline PEM, or a scheme with no refreshable loader. Static until the
    /// configuration itself is reloaded.
    Static,
    /// File-backed source, re-read on the gateway SVID file cadence.
    File(Duration),
    /// Provider-backed source, re-fetched on
    /// `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS` or the source's `?poll=`.
    Provider(Duration),
}

impl GatewaySvidCadence {
    /// The refresh interval, or `None` for a static source.
    pub fn interval(self) -> Option<Duration> {
        match self {
            Self::Static => None,
            Self::File(interval) | Self::Provider(interval) => Some(interval),
        }
    }

    /// `true` when the source can change underneath the running process.
    pub fn is_refreshable(self) -> bool {
        self.interval().is_some()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::File(_) => "file",
            Self::Provider(_) => "provider",
        }
    }
}

/// Classify one configured source into its refresh cadence.
pub fn gateway_svid_cadence(
    source: &CertSource,
    file_default: Duration,
    provider_default: Duration,
) -> GatewaySvidCadence {
    let Some(interval) = source_poll_interval(source, file_default, provider_default) else {
        return GatewaySvidCadence::Static;
    };
    // Inline PEM never yields an interval, so anything left that is not a local
    // file is provider-backed: the secret managers plus `k8s://`, `acme://`,
    // and `managed://`.
    let file_backed = match source {
        CertSource::Path(_) => true,
        CertSource::Uri(uri) => uri.scheme == SourceScheme::File,
        CertSource::InlinePem(_) => false,
    };
    if file_backed {
        GatewaySvidCadence::File(interval)
    } else {
        GatewaySvidCadence::Provider(interval)
    }
}

/// The three configured gateway SVID material sources.
///
/// Holds both the parsed [`CertSource`]s (for fingerprinting) and the original
/// configured values (for the reload, which goes through the same loader that
/// startup and `POST /admin/tls/rotate/svid` use).
#[derive(Clone)]
pub struct GatewaySvidSourceSet {
    cert_value: String,
    key_value: String,
    trust_bundle_value: String,
    expected_spiffe_id: Option<String>,
    watched: Vec<WatchedMaterialSource>,
}

impl GatewaySvidSourceSet {
    pub fn new(
        cert_value: String,
        key_value: String,
        trust_bundle_value: String,
        expected_spiffe_id: Option<String>,
    ) -> Self {
        let cert = CertSource::parse(cert_value.as_str(), MaterialKind::Cert);
        let key = CertSource::parse(key_value.as_str(), MaterialKind::Key);
        let bundle = CertSource::parse(trust_bundle_value.as_str(), MaterialKind::CaBundle);
        let watched = vec![
            WatchedMaterialSource::new(CERT_LABEL, cert, MaterialKind::Cert),
            WatchedMaterialSource::new(KEY_LABEL, key, MaterialKind::Key),
            WatchedMaterialSource::new(TRUST_BUNDLE_LABEL, bundle, MaterialKind::CaBundle),
        ];
        Self {
            cert_value,
            key_value,
            trust_bundle_value,
            expected_spiffe_id,
            watched,
        }
    }

    pub fn watched_sources(&self) -> &[WatchedMaterialSource] {
        &self.watched
    }

    /// Re-read all three sources and validate them as one SVID bundle.
    pub fn load_bundle(&self) -> Result<SvidBundle, SpiffeTlsError> {
        crate::identity::file_loader::load_svid_bundle_from_sources(
            &self.cert_value,
            &self.key_value,
            &self.trust_bundle_value,
            self.expected_spiffe_id.as_deref(),
        )
    }
}

/// One source that could not be re-read on this pass.
#[derive(Debug, Clone)]
pub struct GatewaySvidSourceFailure {
    pub label: &'static str,
    pub kind: MaterialKind,
    pub scheme: SourceScheme,
    /// Fixed-cardinality class retained by transition dedup and event records.
    pub failure_class: &'static str,
    /// Already-redacted loader error: `MaterialError`'s producers withhold
    /// provider references before the error is constructed.
    pub error: String,
}

/// What one tracker pass concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewaySvidPollOutcome {
    /// No source was due, or a source has not recovered yet.
    Idle,
    /// The first complete read established the comparison baseline.
    Baseline,
    /// Every source that was due is rotation-equivalent to the published set
    /// (same source identity, material bytes, kind, and scheme; provider
    /// `version` may differ).
    Unchanged,
    /// At least one source is not rotation-equivalent; the caller should reload.
    Changed,
    /// A due source could not be read; the caller keeps the last-good bundle.
    SourceUnavailable,
}

/// Result of one tracker pass.
#[derive(Debug, Clone)]
pub struct GatewaySvidPollReport {
    pub outcome: GatewaySvidPollOutcome,
    /// Entries successfully re-read on this pass — only the sources that were
    /// due, never the whole set.
    pub refreshed: Vec<MaterialFingerprintEntry>,
    pub failures: Vec<GatewaySvidSourceFailure>,
}

struct TrackedSource {
    watched: WatchedMaterialSource,
    cadence: GatewaySvidCadence,
    last: Option<MaterialFingerprintEntry>,
    unavailable: bool,
    due_at: Option<Instant>,
}

/// Per-source fingerprint tracker for the gateway SVID material set.
///
/// Each source is re-read on its own cadence; the *set* of latest fingerprints
/// is what [`gateway_svid_rotation_equivalent`] compares, so a material-byte
/// or source-identity change on any one member triggers one coherent reload of
/// all three. Provider `version` is retained on entries for observability but
/// is not part of that predicate.
pub struct GatewaySvidSourceTracker {
    sources: Vec<TrackedSource>,
    published: Option<Vec<MaterialFingerprintEntry>>,
    /// Latched by a [`GatewaySvidSourceTracker::prime`] that established no
    /// baseline. While set, the first complete fingerprint set is reported as
    /// [`GatewaySvidPollOutcome::Changed`] instead of
    /// [`GatewaySvidPollOutcome::Baseline`], so it is reloaded and published
    /// rather than silently adopted. Cleared by [`Self::commit`], i.e. only
    /// once a coherent bundle for those exact fingerprints is live.
    forced_first_publish: bool,
}

impl GatewaySvidSourceTracker {
    pub fn new(
        sources: &GatewaySvidSourceSet,
        file_default: Duration,
        provider_default: Duration,
    ) -> Self {
        let mut tracked = Vec::with_capacity(sources.watched_sources().len());
        for watched in sources.watched_sources() {
            let source = &watched.source;
            let cadence = gateway_svid_cadence(source, file_default, provider_default);
            tracked.push(TrackedSource {
                watched: watched.clone(),
                cadence,
                last: None,
                unavailable: false,
                due_at: None,
            });
        }
        Self {
            sources: tracked,
            published: None,
            forced_first_publish: false,
        }
    }

    /// Configured cadence per source label, in cert / key / trust-bundle order.
    pub fn cadences(&self) -> Vec<(&'static str, GatewaySvidCadence)> {
        let mut cadences = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            cadences.push((source.watched.label, source.cadence));
        }
        cadences
    }

    /// `true` when at least one source can change underneath the process.
    pub fn is_watchable(&self) -> bool {
        self.sources.iter().any(|s| s.cadence.is_refreshable())
    }

    /// Re-read every source whose cadence is due and compare the resulting set
    /// against the last published one.
    pub fn poll(&mut self, now: Instant) -> GatewaySvidPollReport {
        let mut refreshed = Vec::new();
        let mut failures = Vec::new();

        for source in &mut self.sources {
            let due = match source.due_at {
                // A static source is fingerprinted once so it participates in
                // set equality, then never again.
                None => source.last.is_none(),
                Some(due_at) => due_at <= now,
            };
            if !due {
                continue;
            }
            if let Some(interval) = source.cadence.interval() {
                source.due_at = Some(now + interval);
            }
            match material_fingerprint(&source.watched) {
                Ok(entry) => {
                    refreshed.push(entry.clone());
                    source.last = Some(entry);
                    source.unavailable = false;
                }
                Err(error) => {
                    source.unavailable = true;
                    failures.push(GatewaySvidSourceFailure {
                        label: source.watched.label,
                        kind: source.watched.kind,
                        scheme: configured_scheme(&source.watched.source),
                        failure_class: error.failure_class(),
                        error: error.to_string(),
                    });
                }
            }
        }

        if !failures.is_empty() {
            return GatewaySvidPollReport {
                outcome: GatewaySvidPollOutcome::SourceUnavailable,
                refreshed,
                failures,
            };
        }

        if self.sources.iter().any(|source| source.unavailable) {
            // Another source with a slower cadence is still unavailable from
            // an earlier pass. A successful read of a faster source is not
            // recovery and must not re-enable its warning or compare a set
            // containing the unavailable source's stale fingerprint.
            return GatewaySvidPollReport {
                outcome: GatewaySvidPollOutcome::Idle,
                refreshed,
                failures,
            };
        }

        let Some(current) = self.current_fingerprints() else {
            // A source failed on an earlier pass and is not due again yet.
            return GatewaySvidPollReport {
                outcome: GatewaySvidPollOutcome::Idle,
                refreshed,
                failures,
            };
        };

        let outcome = self.classify_complete_set(current);
        GatewaySvidPollReport {
            outcome,
            refreshed,
            failures,
        }
    }

    /// Async runtime equivalent of [`Self::poll`]. Source reads use the shared
    /// bounded/deadlined TLS source executor, so a stalled provider cannot park
    /// the Tokio worker that owns the SVID cadence.
    pub async fn poll_async(&mut self, now: Instant) -> GatewaySvidPollReport {
        let mut refreshed = Vec::new();
        let mut failures = Vec::new();

        for source in &mut self.sources {
            let due = match source.due_at {
                None => source.last.is_none(),
                Some(due_at) => due_at <= now,
            };
            if !due {
                continue;
            }
            if let Some(interval) = source.cadence.interval() {
                source.due_at = Some(now + interval);
            }
            match material_fingerprint_async(&source.watched).await {
                Ok(entry) => {
                    refreshed.push(entry.clone());
                    source.last = Some(entry);
                    source.unavailable = false;
                }
                Err(error) => {
                    source.unavailable = true;
                    failures.push(GatewaySvidSourceFailure {
                        label: source.watched.label,
                        kind: source.watched.kind,
                        scheme: configured_scheme(&source.watched.source),
                        failure_class: error.failure_class(),
                        error: error.to_string(),
                    });
                }
            }
        }

        if !failures.is_empty() {
            return GatewaySvidPollReport {
                outcome: GatewaySvidPollOutcome::SourceUnavailable,
                refreshed,
                failures,
            };
        }
        if self.sources.iter().any(|source| source.unavailable) {
            return GatewaySvidPollReport {
                outcome: GatewaySvidPollOutcome::Idle,
                refreshed,
                failures,
            };
        }
        let Some(current) = self.current_fingerprints() else {
            return GatewaySvidPollReport {
                outcome: GatewaySvidPollOutcome::Idle,
                refreshed,
                failures,
            };
        };
        let outcome = self.classify_complete_set(current);
        GatewaySvidPollReport {
            outcome,
            refreshed,
            failures,
        }
    }

    fn classify_complete_set(
        &mut self,
        current: Vec<MaterialFingerprintEntry>,
    ) -> GatewaySvidPollOutcome {
        if self.published.is_none() {
            if self.forced_first_publish {
                // The synchronous startup prime never read a complete set, so
                // there is no anchor proving the live slot matches these bytes:
                // a source that was unreadable at prime time may have rotated
                // between the recovery read that produced the live bundle and
                // now. Adopting this set as a quiet baseline would strand the
                // live slot on the older material until something changed
                // again. Report a change and leave `published` unset so the
                // coherent reload path publishes and only then commits.
                GatewaySvidPollOutcome::Changed
            } else {
                self.published = Some(current);
                GatewaySvidPollOutcome::Baseline
            }
        } else if self
            .published
            .as_ref()
            .is_some_and(|published| gateway_svid_rotation_equivalent(published, &current))
        {
            // Refresh published when only ignored fields (provider version)
            // drifted, so observability keeps the latest metadata without
            // treating that drift as a rotation. Full equality here avoids a
            // redundant clone when nothing changed at all.
            if self.published.as_ref() != Some(&current) {
                self.published = Some(current);
            }
            GatewaySvidPollOutcome::Unchanged
        } else {
            GatewaySvidPollOutcome::Changed
        }
    }

    /// Establish the comparison baseline from the sources as they are *now*.
    ///
    /// This must run **synchronously at startup, before the initial SVID
    /// bundle is loaded into the live slot**, not lazily on the watcher task's
    /// first scheduled poll. The spawned task does not run until the caller
    /// yields to the runtime, and the gap between `ProxyState::new` and that
    /// first yield covers the rest of gateway startup (TLS policy, listener
    /// binds, DNS warmup). A source rewritten inside that window would be
    /// adopted *as* the baseline, so the change is never observed and the
    /// gateway keeps serving the pre-rotation identity until the material
    /// happens to change again — precisely the silent-staleness this watcher
    /// exists to prevent.
    ///
    /// Priming before the bundle load keeps the failure direction safe: the
    /// baseline can only be older than or equal to what the live slot holds,
    /// so a startup-window change costs one redundant rotation rather than a
    /// stale identity.
    ///
    /// A prime that could not read every source establishes no baseline, and
    /// the startup bundle load that follows it may still succeed — the sources
    /// are re-read, so a transiently unavailable one can have recovered in
    /// between. That leaves the live slot holding material this tracker never
    /// fingerprinted, and a later rotation of the previously unreadable source
    /// would otherwise be adopted as the baseline and never published. Such a
    /// prime therefore latches [`Self::forced_first_publish_pending`], which
    /// routes the first complete fingerprint set through the coherent
    /// reload-and-publish path instead.
    pub fn prime(&mut self, now: Instant) -> GatewaySvidPollOutcome {
        let outcome = self.poll(now).outcome;
        // Keyed on the baseline actually being unset rather than on the
        // outcome variant, so any pass that fails to anchor one — an
        // unreadable source, or a set that is still incomplete — latches the
        // forced publish.
        if self.published.is_none() {
            self.forced_first_publish = true;
        }
        outcome
    }

    /// `true` while a failed or incomplete prime is still waiting for its
    /// forced first reload-and-publish to succeed.
    pub fn forced_first_publish_pending(&self) -> bool {
        self.forced_first_publish
    }

    /// Adopt the current fingerprints as the comparison baseline.
    ///
    /// Called only after the corresponding coherent bundle is already live.
    /// A failed reload deliberately leaves the prior published fingerprints in
    /// place so a recovered provider is retried even when its bytes did not
    /// change again. For the same reason a forced first publish is released
    /// here, and only here: a failed reload keeps the latch, so the retry
    /// survives until a coherent bundle is genuinely live.
    pub fn commit(&mut self) {
        if let Some(current) = self.current_fingerprints() {
            self.published = Some(current);
            self.forced_first_publish = false;
        }
    }

    /// Latest fingerprints, or `None` while any source has never been read.
    pub fn current_fingerprints(&self) -> Option<Vec<MaterialFingerprintEntry>> {
        let mut entries = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            entries.push(source.last.clone()?);
        }
        Some(entries)
    }

    /// How long to sleep before the next source is due.
    pub fn next_delay(&self, now: Instant) -> Duration {
        let mut delay = MAX_WATCH_SLEEP;
        for source in &self.sources {
            let Some(due_at) = source.due_at else {
                continue;
            };
            delay = delay.min(due_at.saturating_duration_since(now));
        }
        delay
    }
}

fn configured_scheme(source: &CertSource) -> SourceScheme {
    match source {
        CertSource::Path(_) | CertSource::InlinePem(_) => SourceScheme::File,
        CertSource::Uri(uri) => uri.scheme,
    }
}

/// Install a validated bundle and return the new backend SVID generation.
///
/// Production wires this to `ProxyState::install_gateway_file_svid_bundle` plus
/// a `backend_svid_rotation_tx` bump, so the slot update strictly precedes the
/// generation bump that backend pools, health probes, and pool keys observe.
pub type GatewaySvidPublishFn = Box<dyn Fn(SvidBundle) -> u64 + Send + Sync + 'static>;

/// Configuration for [`run_gateway_svid_source_rotation_loop`].
pub struct GatewaySvidWatchConfig {
    pub sources: GatewaySvidSourceSet,
    /// Cadence for file-backed sources.
    pub file_interval: Duration,
    /// Cadence for provider-backed sources without an explicit `?poll=`
    /// (`FERRUM_SECRET_REFRESH_INTERVAL_SECONDS`).
    pub provider_interval: Duration,
    /// Tracker already primed by the caller via
    /// [`GatewaySvidSourceTracker::prime`]. Production always supplies one so
    /// the baseline is anchored to startup rather than to whenever the spawned
    /// task is first scheduled. `None` builds the tracker here and baselines on
    /// the first poll, which is only correct when the sources cannot have
    /// changed since they were configured.
    pub tracker: Option<GatewaySvidSourceTracker>,
    pub publish: GatewaySvidPublishFn,
}

/// Poll the configured gateway SVID sources and republish the bundle on change.
///
/// Exits immediately when every configured source is static, and cleanly when
/// the shutdown receiver fires.
pub async fn run_gateway_svid_source_rotation_loop(
    config: GatewaySvidWatchConfig,
    mut shutdown_rx: Option<watch::Receiver<bool>>,
) {
    let GatewaySvidWatchConfig {
        sources,
        file_interval,
        provider_interval,
        tracker,
        publish,
    } = config;

    let mut tracker = tracker.unwrap_or_else(|| {
        GatewaySvidSourceTracker::new(&sources, file_interval, provider_interval)
    });
    if !tracker.is_watchable() {
        info!(
            "Gateway SVID sources are all static (inline PEM); automatic refresh is disabled — \
             update the configured literal and reload configuration or restart to rotate"
        );
        return;
    }

    for (label, cadence) in tracker.cadences() {
        let interval_secs = cadence.interval().map(|i| i.as_secs()).unwrap_or(0);
        info!(
            source = label,
            cadence = cadence.as_str(),
            interval_secs,
            "Gateway SVID source refresh cadence"
        );
    }

    let mut reporter = FailureReporter::default();

    loop {
        if shutdown_rx.as_ref().is_some_and(|rx| *rx.borrow()) {
            return;
        }

        let report = tracker.poll_async(Instant::now()).await;
        match report.outcome {
            GatewaySvidPollOutcome::Idle | GatewaySvidPollOutcome::Baseline => {}
            GatewaySvidPollOutcome::SourceUnavailable => {
                record_source_failures(&sources, &report.failures, &mut reporter);
            }
            GatewaySvidPollOutcome::Unchanged => {
                note_recovery(&mut reporter, &sources);
                record_refresh_for_entries(GATEWAY_SVID_SURFACE, &report.refreshed, "unchanged");
            }
            GatewaySvidPollOutcome::Changed => {
                reload_and_publish(&sources, &mut tracker, publish.as_ref(), &mut reporter).await;
            }
        }

        let delay = tracker.next_delay(Instant::now());
        if let Some(shutdown) = shutdown_rx.as_mut() {
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
            }
        } else {
            tokio::time::sleep(delay).await;
        }
    }
}

/// Warn-once **and record-once** state for a failing pass.
///
/// Retrying is deliberate: a source that stays unreadable, and a candidate
/// whose coherent reload keeps failing, are both re-attempted on every source
/// cadence so a recovered provider publishes without needing another material
/// change. The *reporting* must not follow that cadence. [`crate::tls::events`]
/// is a bounded ring that re-serializes its full contents and atomically
/// rewrites its on-disk store on every record, and marks the TLS inventory
/// cache stale; a file-backed source failing on the 1s cadence would therefore
/// rewrite that store once per second indefinitely and, within the ring's
/// capacity, evict every other TLS surface's rotation history from both the
/// in-memory log and the persisted file.
///
/// Each distinct failing state is therefore recorded and warned exactly once,
/// and re-armed when that state changes or the source recovers. The two failure
/// classes latch independently rather than superseding each other, so a source
/// that flaps between unreadable and readable-but-refused still records one
/// event per distinct state instead of one per poll. The
/// `ferrum_tls_source_refresh_total` counters stay per attempt, so `rate()`
/// still shows the retry loop running.
#[derive(Default)]
struct FailureReporter {
    /// Labels of the sources that could not be read on the last reported pass.
    unavailable: Option<Vec<(&'static str, &'static str)>>,
    /// Candidate fingerprints of the last reported unpublishable reload.
    rebuild: Option<Vec<MaterialFingerprintEntry>>,
}

impl FailureReporter {
    /// `true` when this exact set of unreadable sources is not already
    /// reported.
    fn arm_unavailable(&mut self, failures: &[GatewaySvidSourceFailure]) -> bool {
        let classes = failures
            .iter()
            .map(|failure| (failure.label, failure.failure_class))
            .collect::<Vec<_>>();
        if self.unavailable.as_deref() == Some(classes.as_slice()) {
            return false;
        }
        self.unavailable = Some(classes);
        true
    }

    /// `true` when this candidate is not already reported as an unpublishable
    /// reload. Uses [`gateway_svid_rotation_equivalent`] so a provider-version
    /// bump on the same refused bytes does not rewrite the TLS event store.
    fn arm_rebuild(&mut self, entries: &[MaterialFingerprintEntry]) -> bool {
        if self
            .rebuild
            .as_ref()
            .is_some_and(|prior| gateway_svid_rotation_equivalent(prior, entries))
        {
            return false;
        }
        self.rebuild = Some(entries.to_vec());
        true
    }

    /// Disarm on recovery. `true` when a failure was actually pending.
    fn clear(&mut self) -> (bool, bool) {
        let had_unavailable = self.unavailable.take().is_some();
        let had_rebuild = self.rebuild.take().is_some();
        (had_unavailable, had_rebuild)
    }
}

fn note_recovery(reporter: &mut FailureReporter, sources: &GatewaySvidSourceSet) {
    let (had_unavailable, had_rebuild) = reporter.clear();
    if had_unavailable {
        crate::tls::events::record_load_recovery(GATEWAY_SVID_SURFACE, sources.watched_sources());
    }
    if had_unavailable || had_rebuild {
        info!("Gateway SVID source watcher recovered source access");
    }
}

fn record_source_failures(
    sources: &GatewaySvidSourceSet,
    failures: &[GatewaySvidSourceFailure],
    reporter: &mut FailureReporter,
) {
    let registry = crate::plugins::prometheus_metrics::global_registry();
    for failure in failures {
        registry.record_tls_source_refresh(
            failure.scheme.as_str(),
            failure.kind.as_str(),
            GATEWAY_SVID_SURFACE,
            "load_error",
        );
    }

    // The read itself is retried on every cadence; the event record and the
    // warning are armed once per distinct outage. See `FailureReporter`.
    if !reporter.arm_unavailable(failures) {
        return;
    }

    // Only the sources that actually failed are attributed; a trust-bundle
    // fetch outage must not be recorded as a certificate failure.
    let mut failed = Vec::new();
    for watched in sources.watched_sources() {
        if failures.iter().any(|f| f.label == watched.label) {
            failed.push(watched.clone());
        }
    }
    let detail = describe_failures(failures);
    let failure_classes = describe_failure_classes(failures);
    record_load_error(GATEWAY_SVID_SURFACE, &failed, &failure_classes);
    warn!(
        error = %detail,
        "Gateway SVID source could not be read; keeping the current SVID material \
         (silenced until the source recovers or the failing set changes)"
    );
}

async fn reload_and_publish(
    sources: &GatewaySvidSourceSet,
    tracker: &mut GatewaySvidSourceTracker,
    publish: &(dyn Fn(SvidBundle) -> u64 + Send + Sync),
    reporter: &mut FailureReporter,
) {
    let entries = tracker.current_fingerprints().unwrap_or_default();
    // One coherent re-read of all three sources. If a source changes again
    // between the fingerprint pass and this load, the committed fingerprints
    // are older than the published material, so the next pass compares unequal
    // and reloads again — a redundant rotation, never a stale identity.
    let sources_for_load = sources.clone();
    let load_result = match crate::tls::source::run_tls_source_blocking_result(move || {
        sources_for_load.load_bundle()
    })
    .await
    {
        Ok(result) => result.map_err(anyhow::Error::new),
        Err(error) => Err(anyhow::Error::new(error)),
    };
    match load_result {
        Ok(bundle) => {
            note_recovery(reporter, sources);
            let spiffe_id = bundle.spiffe_id.to_string();
            let revision = publish(bundle);
            tracker.commit();
            record_refresh_for_entries(GATEWAY_SVID_SURFACE, &entries, "rotated");
            record_rotation_success(GATEWAY_SVID_SURFACE, &entries, revision);
            info!(
                spiffe_id = %spiffe_id,
                svid_revision = revision,
                "Gateway SVID sources reloaded; backend SVID rotation published"
            );
        }
        Err(error) => {
            // Keep the last *published* fingerprint. The coherent bundle load
            // re-fetches all three sources after the fingerprint pass, so it
            // can fail transiently even when the observed bytes are stable.
            // Committing a failed candidate would suppress every future retry
            // until a source changed again, leaving a recovered provider stuck
            // on the old SVID. Retaining the published fingerprint retries on
            // the next source cadence; the event record and the warning are
            // armed once per distinct candidate so that retry does not rewrite
            // the bounded TLS event store on every poll. See `FailureReporter`.
            record_refresh_for_entries(GATEWAY_SVID_SURFACE, &entries, "rebuild_error");
            if !reporter.arm_rebuild(&entries) {
                return;
            }
            let error = anyhow::anyhow!("{error}");
            record_rebuild_error(GATEWAY_SVID_SURFACE, &entries, &error);
            warn!(
                error = %error,
                "Gateway SVID sources changed but the reload failed; keeping the current \
                 material (silenced until a coherent reload succeeds or the candidate changes)"
            );
        }
    }
}

fn describe_failures(failures: &[GatewaySvidSourceFailure]) -> String {
    let mut rendered = Vec::with_capacity(failures.len());
    for failure in failures {
        rendered.push(format!("{}: {}", failure.label, failure.error));
    }
    rendered.join("; ")
}

fn describe_failure_classes(failures: &[GatewaySvidSourceFailure]) -> String {
    let mut rendered = Vec::with_capacity(failures.len());
    for failure in failures {
        rendered.push(format!("{}:{}", failure.label, failure.failure_class));
    }
    rendered.join(",")
}
