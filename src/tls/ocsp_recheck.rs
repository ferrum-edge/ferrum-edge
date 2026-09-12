//! Periodic re-validation of served OCSP staples (issue #4505, item 4).
//!
//! A stapled response is validated once, while the frontend/admin TLS
//! candidate is being built ([`crate::tls::load_frontend_tls_candidate`]).
//! Nothing re-checked it afterwards: without
//! `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` the same bytes were stapled to
//! every later handshake forever, and with live reload they were replaced only
//! when the source's bytes changed. A response that passed its `nextUpdate`
//! while the gateway ran therefore kept being served.
//!
//! Serving an expired staple is strictly worse than serving none. A client that
//! enforces staple validity — a `status_request` must-staple certificate, a
//! browser with OCSP checking on — aborts the handshake on an expired response,
//! whereas an absent staple falls back to that client's own revocation
//! behaviour. So this module drops it.
//!
//! **Why the resolver and not a `ServerConfig` rebuild.** The rebuild closures
//! in `crate::modes::tls_reload` exist only when live reload is enabled, and
//! they re-read and re-validate the OCSP source — which, for a staple that has
//! reached `nextUpdate`, fails and keeps the previous (stale-stapled) config.
//! Retiring the staple inside the resolver instead works on both postures, and
//! because the HTTP/3 listener rebuilds its TLS 1.3-only config around **the
//! same certificate resolver** (`tls_config.cert_resolver.clone()` in
//! `crate::http3::server`), one atomic store reaches HTTP/1.1, HTTP/2, HTTP/3,
//! TCP+TLS, and the admin listener together.
//!
//! Live reload still re-attaches a refreshed staple by its ordinary path: an
//! accepted rebuild constructs a *new* resolver carrying the new response and
//! publishes a new `ServerConfig`, and that load registers here in turn. The
//! superseded resolver is held only by a [`Weak`], so it is pruned as soon as
//! the config that owned it is dropped.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use tracing::{debug, info, warn};
use x509_parser::prelude::ASN1Time;

use crate::tls::acme::AcmeTlsAlpnResolver;

/// How often a served staple is re-validated.
///
/// Deliberately a constant, not an operator knob: the value an operator would
/// set is not a policy choice but a bound on how long an expired staple may
/// keep being served, and an hour is already far below the shortest `nextUpdate`
/// window any responder issues. Another `FERRUM_*` variable here would only add
/// a way to disable the protection.
pub const STAPLE_RECHECK_INTERVAL: Duration = Duration::from_secs(3600);

/// Upper bound on tracked staples. One entry per serving surface (proxy
/// frontend, admin frontend) per accepted generation, and dead generations are
/// pruned on every registration and every run, so this is only a guard against
/// a pathological reload loop retaining entries faster than they are collected.
const MAX_TRACKED_STAPLES: usize = 64;

/// One accepted staple, tracked against the exact resolver serving it.
struct TrackedStaple {
    /// The resolver inside the published `ServerConfig`. `Weak` so a
    /// superseded generation is pruned rather than kept alive by this registry.
    resolver: Weak<AcmeTlsAlpnResolver>,
    /// The operator's configured source string, i.e. the TLS inventory's
    /// `source.identifier`. Never logged.
    configured_source_id: String,
    /// The already-redacted source display id, safe to log.
    display_source_id: String,
    /// `nextUpdate` of the accepted `SingleResponse`.
    next_update: i64,
    /// `FERRUM_TLS_CRL_EXPIRY_WARNING_DAYS` as it was when this staple was
    /// accepted, so the periodic re-warn uses the same window the load-time
    /// warning did.
    warning_days: u64,
}

struct Registry {
    tracked: Mutex<Vec<TrackedStaple>>,
    /// Configured source ids whose staple this process dropped, with the
    /// `nextUpdate` that was dropped. Read by the TLS inventory so an entry
    /// stops advertising a deadline for material that is no longer served.
    dropped: Mutex<Vec<(String, i64)>>,
    task_started: AtomicBool,
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry {
        tracked: Mutex::new(Vec::new()),
        dropped: Mutex::new(Vec::new()),
        task_started: AtomicBool::new(false),
    })
}

/// Outcome of one re-check pass, returned for tests and for the spawned task's
/// own bookkeeping.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecheckOutcome {
    /// Staples still served after this pass.
    pub tracked: usize,
    /// Staples retired by this pass because they reached `nextUpdate`.
    pub dropped: usize,
    /// Staples inside the lead-time warning window that were re-warned.
    pub warned: usize,
}

/// A certificate resolver whose stapled OCSP response can be retired at
/// runtime.
///
/// [`AcmeTlsAlpnResolver`] either serves one certificate directly or delegates
/// to an inner resolver — today the Gateway multi-certificate SNI index in
/// [`crate::tls::multi_cert`]. Both arms can carry a staple, so both must be
/// able to give one up. An inner resolver that could not would be a
/// certificate source silently exempt from this module, which is precisely the
/// gap issue #4773 reported: the Gateway frontend validated a staple, recorded
/// its `nextUpdate`, and then had no way to stop serving it.
pub trait StapleRetiringResolver: rustls::server::ResolvesServerCert {
    /// Retire the stapled OCSP response this resolver serves, returning
    /// whether one was actually removed.
    ///
    /// Must publish atomically: a handshake running concurrently with the
    /// retirement has to observe either the stapled or the stapleless
    /// credential, never a torn one, and must not block on the retirement.
    fn drop_stapled_ocsp_response(&self) -> bool;
}

/// What a staple is being attached to, for the operator-facing rejection
/// message and the acceptance log record.
#[derive(Clone, Copy)]
pub(crate) enum StapleTarget<'a> {
    /// The operator-configured single-certificate frontend/admin listener.
    ConfiguredListener,
    /// One Gateway-delivered certificate, named by its public
    /// `serving-namespace/serialized-owner/listener` identity.
    GatewayCertificate(&'a str),
}

impl StapleTarget<'_> {
    /// The operator-facing refusal, worded for the surface that configured the
    /// response. Carries the redacted display id only.
    fn rejection(self, display_source_id: &str, error: impl std::fmt::Display) -> anyhow::Error {
        match self {
            Self::ConfiguredListener => {
                anyhow::anyhow!("OCSP response source '{display_source_id}' was rejected: {error}")
            }
            Self::GatewayCertificate(identity) => anyhow::anyhow!(
                "Gateway certificate {identity} was configured with a stapled OCSP response that \
                 was rejected: {error}"
            ),
        }
    }
}

/// A staple that passed certificate-bound validation and is about to be
/// served.
///
/// Constructed only by [`accept_stapled_response`] and consumed only by
/// [`AcceptedStaple::enroll`]: that pair is the single "accept a staple"
/// contract every certificate source goes through, so a third source cannot
/// repeat issue #4773 by validating a response and forgetting to enrol it.
/// [`register_stapled_response`] is deliberately private to this module for
/// the same reason.
#[must_use = "an accepted staple that is never enrolled is never retired; call `enroll`"]
pub(crate) struct AcceptedStaple {
    /// The operator's configured source string — the TLS inventory's
    /// `source.identifier`, so the two agree about which entry was retired.
    configured_source_id: String,
    /// The already-redacted display id, the only form ever logged.
    display_source_id: String,
    next_update: i64,
    /// `FERRUM_TLS_CRL_EXPIRY_WARNING_DAYS` at acceptance, so the periodic
    /// re-warn uses the same window the load-time warning did.
    warning_days: u64,
}

impl AcceptedStaple {
    /// Hand this staple, and the resolver that will serve it, to the periodic
    /// re-check.
    ///
    /// Registration happens whether or not live reload is enabled — without it
    /// there is no other event that could ever revisit these bytes. The
    /// registry holds only a [`Weak`], so a resolver that is never published
    /// (a rejected reload, a `validate` run) drops out on its own.
    pub(crate) fn enroll(self, resolver: &Arc<AcmeTlsAlpnResolver>) {
        register_stapled_response(
            resolver,
            self.configured_source_id,
            self.display_source_id,
            self.next_update,
            self.warning_days,
        );
    }
}

/// Validate `response` against the chain that will serve it, log the
/// acceptance, fire the lead-time warning, and return the record that must be
/// enrolled.
///
/// Every certificate source shares this one definition (issue #4773, refs
/// #4792): the single-certificate frontend/admin loader in
/// [`crate::tls::load_frontend_tls_candidate`] and the Gateway
/// multi-certificate loader in [`crate::tls::multi_cert`]. Ferrum has no OCSP
/// responder client, so nothing inside the gateway re-fetches these bytes; the
/// warning is the operator's cue to refresh before the deadline, and the
/// re-check armed by [`AcceptedStaple::enroll`] re-fires it hourly while the
/// staple stays inside the window and retires the staple outright once it
/// reaches `nextUpdate`.
pub(crate) fn accept_stapled_response(
    response: &[u8],
    cert_chain: &[CertificateDer<'_>],
    target: StapleTarget<'_>,
    configured_source_id: String,
    display_source_id: String,
    revocation_expiry_warning_days: u64,
) -> Result<AcceptedStaple, anyhow::Error> {
    let acceptance = crate::tls::ocsp::validate_stapled_response(response, cert_chain)
        .map_err(|error| target.rejection(&display_source_id, error))?;
    match target {
        StapleTarget::ConfiguredListener => info!(
            ocsp_source = %display_source_id,
            ocsp_der_bytes = acceptance.der_len,
            ocsp_this_update = acceptance.this_update,
            ocsp_next_update = acceptance.next_update,
            ocsp_delegated_responder = acceptance.delegated_responder,
            "Validated and stapled OCSP response for server TLS config"
        ),
        StapleTarget::GatewayCertificate(identity) => info!(
            gateway_certificate = %identity,
            ocsp_source = %display_source_id,
            ocsp_der_bytes = acceptance.der_len,
            ocsp_this_update = acceptance.this_update,
            ocsp_next_update = acceptance.next_update,
            ocsp_delegated_responder = acceptance.delegated_responder,
            "Validated and stapled OCSP response for Gateway certificate"
        ),
    }
    crate::tls::warn_if_revocation_material_near_expiry(
        "ocsp",
        &display_source_id,
        acceptance.next_update,
        revocation_expiry_warning_days,
        ASN1Time::now().timestamp(),
    );
    Ok(AcceptedStaple {
        configured_source_id,
        display_source_id,
        next_update: acceptance.next_update,
        warning_days: revocation_expiry_warning_days,
    })
}

/// Record an accepted staple so the periodic re-check can retire it.
///
/// Called by the loader that actually serves the response, with the resolver it
/// installed. Registering also starts the process-wide re-check task the first
/// time it is reached from inside a tokio runtime — a `validate` run, which
/// loads the same material without a runtime, registers without spawning
/// anything.
fn register_stapled_response(
    resolver: &Arc<AcmeTlsAlpnResolver>,
    configured_source_id: String,
    display_source_id: String,
    next_update: i64,
    warning_days: u64,
) {
    let registry = registry();
    if let Ok(mut tracked) = registry.tracked.lock() {
        tracked.retain(|entry| entry.resolver.strong_count() > 0);
        if tracked.len() >= MAX_TRACKED_STAPLES {
            tracked.remove(0);
        }
        tracked.push(TrackedStaple {
            resolver: Arc::downgrade(resolver),
            configured_source_id: configured_source_id.clone(),
            display_source_id,
            next_update,
            warning_days,
        });
    }
    // A newly accepted staple for this source supersedes any earlier drop: the
    // inventory must go back to reporting the deadline that is now served.
    if let Ok(mut dropped) = registry.dropped.lock() {
        dropped.retain(|(source_id, _)| source_id != &configured_source_id);
    }
    ensure_recheck_task();
}

/// The `nextUpdate` this process dropped for `configured_source_id`, if any.
///
/// The TLS inventory consults this so an OCSP entry whose staple was retired at
/// runtime reports the retirement instead of the stale deadline still sitting
/// in the source's bytes — and, because the revocation gauge is derived from
/// `TlsInventoryEntry::next_update`, so the
/// `ferrum_tls_revocation_expiry_seconds{kind="ocsp"}` row for it disappears
/// rather than reporting an ever more negative countdown for material nothing
/// serves.
pub fn dropped_staple_next_update(configured_source_id: &str) -> Option<i64> {
    let dropped = registry().dropped.lock().ok()?;
    dropped
        .iter()
        .find(|(source_id, _)| source_id.as_str() == configured_source_id)
        .map(|(_, next_update)| *next_update)
}

/// Run one re-check pass at `now` (Unix seconds) over every tracked staple.
///
/// Public so tests — and the integration suite's short-lived-staple case — can
/// drive the check directly instead of waiting an hour.
pub fn run_recheck_at(now: i64) -> RecheckOutcome {
    run_recheck_at_scoped(now, None)
}

/// [`run_recheck_at`] restricted to one configured source id.
///
/// The registry is process-wide, so a test that drives a pass at a chosen
/// instant would otherwise also retire staples belonging to unrelated tests
/// running concurrently in the same binary. Scoping the pass to the source the
/// test itself configured keeps that isolation without weakening what the
/// production pass does — which is the same walk with no filter.
pub fn run_recheck_at_scoped(now: i64, only_source: Option<&str>) -> RecheckOutcome {
    let registry = registry();
    let Ok(mut tracked) = registry.tracked.lock() else {
        return RecheckOutcome::default();
    };
    let mut outcome = RecheckOutcome::default();
    let mut newly_dropped: Vec<(String, i64)> = Vec::new();

    tracked.retain(|entry| {
        let Some(resolver) = entry.resolver.upgrade() else {
            // The generation this staple belonged to is no longer served.
            return false;
        };
        if only_source.is_some_and(|source| source != entry.configured_source_id.as_str()) {
            return true;
        }
        if now >= entry.next_update {
            if resolver.drop_stapled_ocsp_response() {
                outcome.dropped += 1;
                newly_dropped.push((entry.configured_source_id.clone(), entry.next_update));
                warn!(
                    revocation_material = "ocsp",
                    source = %entry.display_source_id,
                    next_update = entry.next_update,
                    "Stapled OCSP response reached its nextUpdate and was dropped: this listener \
                     now serves no staple on HTTP/1.1, HTTP/2, HTTP/3 and TCP+TLS. Serving an \
                     expired staple fails the handshake for clients that check it, so no staple \
                     is the safer state. Refresh the OCSP source; with \
                     FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true a fresh response is re-attached \
                     without a restart, otherwise a restart is required — and a must-staple \
                     certificate has no working posture until one of those happens"
                );
            }
            // Stop tracking either way: the staple is gone from this resolver,
            // and a refreshed one arrives as a new registration.
            return false;
        }
        // Still valid. Re-fire the lead-time warning so the operator signal is
        // not load-time only (issue #4505, item 2): once per pass while inside
        // the window, on the same `FERRUM_TLS_CRL_EXPIRY_WARNING_DAYS` window
        // the load-time warning used.
        if crate::tls::warn_if_revocation_material_near_expiry(
            "ocsp",
            &entry.display_source_id,
            entry.next_update,
            entry.warning_days,
            now,
        ) {
            outcome.warned += 1;
        }
        true
    });
    outcome.tracked = match only_source {
        Some(source) => tracked
            .iter()
            .filter(|entry| entry.configured_source_id.as_str() == source)
            .count(),
        None => tracked.len(),
    };
    drop(tracked);

    if !newly_dropped.is_empty()
        && let Ok(mut dropped) = registry.dropped.lock()
    {
        for (source_id, next_update) in newly_dropped {
            dropped.retain(|(existing, _)| existing != &source_id);
            if dropped.len() >= MAX_TRACKED_STAPLES {
                dropped.remove(0);
            }
            dropped.push((source_id, next_update));
        }
    }
    outcome
}

/// Start the process-wide re-check task once, if a tokio runtime is available.
fn ensure_recheck_task() {
    let registry = registry();
    if registry.task_started.load(Ordering::Relaxed) {
        return;
    }
    // No runtime: this is `ferrum-edge validate`, or a startup phase before the
    // multi-threaded runtime exists. Nothing is being served yet either, so the
    // next registration from a serving mode starts the task.
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    if registry
        .task_started
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(STAPLE_RECHECK_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // `interval` yields its first tick immediately; the staple was just
        // validated by the load that registered it, so consume that tick rather
        // than re-warning about material admitted moments ago.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let outcome = run_recheck_at(chrono::Utc::now().timestamp());
            debug!(
                tracked_staples = outcome.tracked,
                dropped_staples = outcome.dropped,
                near_expiry_staples = outcome.warned,
                "Completed a stapled OCSP freshness re-check"
            );
        }
    });
}
