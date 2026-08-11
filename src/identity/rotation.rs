//! SVID rotation task.
//!
//! Periodically inspects the current [`SvidBundle`] and asks the local
//! [`CertificateAuthority`] for a fresh SVID once the current one has
//! crossed half its validity window. The new bundle is hot-swapped via
//! `ArcSwap` so concurrent readers (TLS resolvers) see the swap atomically.
//!
//! This module is intended for the **Ferrum-as-issuer** flow. The
//! **SPIRE-agent flow** uses [`workload_api::fetch_loop`] instead — the
//! agent handles rotation and pushes new SVIDs through its streaming RPC.

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use x509_parser::prelude::*;

use crate::identity::{
    SvidBundle, TrustBundle, TrustBundleSet,
    ca::{IssuanceRequest, SharedCa},
    spiffe::SpiffeId,
};

/// Minimum interval between rotation checks. Even when an SVID has only
/// seconds left to live we don't want to busy-loop.
const MIN_TICK: Duration = Duration::from_secs(5);
/// Maximum interval between rotation checks. Long-lived SVIDs (24h) get
/// re-checked once per minute to handle clock-skew gracefully.
const MAX_TICK: Duration = Duration::from_secs(60);

/// Configuration for the rotation task.
pub struct RotationConfig {
    /// CA used to mint replacement SVIDs.
    pub ca: SharedCa,
    /// SPIFFE ID this rotation task is responsible for.
    pub spiffe_id: SpiffeId,
    /// SVID lifetime to request from the CA.
    pub svid_ttl_secs: u64,
    /// Shared bundle slot. Readers (TLS resolvers) load from this.
    pub current: Arc<ArcSwap<Option<SvidBundle>>>,
    /// Trigger rotation once the current SVID has aged past this fraction
    /// (0.0..=1.0) of its validity window. Default 0.5.
    pub rotate_at_fraction: f64,
    /// Monotonic revision channel bumped after each successful post-initial
    /// rotation. Backend TLS pools subscribe to this to rebuild client identity
    /// configs without restarting.
    ///
    /// Production callers should hand in `ProxyState.backend_svid_rotation_tx`
    /// so the consumer side (`spawn_backend_svid_rotation_task`) observes the
    /// same channel; otherwise the producer/consumer pair drift and the
    /// drain plumbing stays dormant. Construct a fresh channel only for unit
    /// tests that don't have a ProxyState.
    pub revision_tx: watch::Sender<u64>,
}

impl RotationConfig {
    /// Construct a rotation config with an explicit revision sender.
    ///
    /// `revision_tx` is the producer side of the channel
    /// `ProxyState.backend_svid_rotation_tx` is the consumer of. Pass a
    /// `.clone()` of the gateway's sender so revision bumps flow into the
    /// backend pool drain task.
    pub fn new(
        ca: SharedCa,
        spiffe_id: SpiffeId,
        svid_ttl_secs: u64,
        revision_tx: watch::Sender<u64>,
    ) -> Self {
        Self {
            ca,
            spiffe_id,
            svid_ttl_secs,
            current: Arc::new(ArcSwap::new(Arc::new(None))),
            rotate_at_fraction: 0.5,
            revision_tx,
        }
    }

    /// Test-only constructor that synthesizes a private channel.
    #[cfg(test)]
    pub fn new_isolated(ca: SharedCa, spiffe_id: SpiffeId, svid_ttl_secs: u64) -> Self {
        let (revision_tx, _) = watch::channel(0u64);
        Self::new(ca, spiffe_id, svid_ttl_secs, revision_tx)
    }

    pub fn revision_receiver(&self) -> watch::Receiver<u64> {
        self.revision_tx.subscribe()
    }
}

/// Spawn the rotation task. Returns a `JoinHandle`; drop to stop.
pub fn spawn_rotation(config: RotationConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(rotation_main(config))
}

async fn rotation_main(config: RotationConfig) {
    // Mint an initial SVID so callers can bind listeners.
    if let Err(e) = mint_and_install(&config).await {
        crate::plugins::mesh::prometheus_helpers::increment_mesh_cert_rotation_failure(
            &config.spiffe_id,
            "rotation",
        );
        error!(error = %e, "initial SVID issuance failed — rotation task continues");
    }

    loop {
        let snapshot = config.current.load_full();
        let next_tick = match snapshot.as_ref() {
            Some(bundle) => decide_next_tick(bundle, config.rotate_at_fraction),
            None => Duration::from_secs(1),
        };
        sleep(next_tick).await;

        // JWT signing keys rotate on their own schedule, independent of the
        // X.509 SVID's validity window. Driving it from this tick keeps key
        // generation off every request path; the authority itself decides
        // whether anything is due.
        if let Some(generation) = rotate_jwt_authority_if_due(&config.ca).await {
            let revision = bump_revision(&config.revision_tx);
            debug!(
                generation,
                svid_revision = revision,
                "JWT-SVID signing key rotated by rotation task"
            );
        }

        let snapshot = config.current.load_full();
        let needs_rotation = match snapshot.as_ref() {
            Some(bundle) => is_due_for_rotation(bundle, config.rotate_at_fraction),
            None => true,
        };
        if !needs_rotation {
            continue;
        }
        match mint_and_install(&config).await {
            Ok(()) => {
                let revision = bump_revision(&config.revision_tx);
                info!(
                    spiffe_id = %config.spiffe_id,
                    svid_revision = revision,
                    "SVID rotated"
                );
            }
            Err(e) => {
                crate::plugins::mesh::prometheus_helpers::increment_mesh_cert_rotation_failure(
                    &config.spiffe_id,
                    "rotation",
                );
                warn!(error = %e, spiffe_id = %config.spiffe_id, "SVID rotation failed");
            }
        }
    }
}

/// Ask the CA's JWT signing authority — when it has one — to rotate if its
/// active key has outlived its configured lifetime.
///
/// A CA backend without JWT authority (SPIRE agent, the upstream scaffolds)
/// returns `None` from `jwt_signer()` and this is a no-op. A rotation failure
/// is warned and retried on the next tick: the previous key stays active and
/// every already-minted token remains verifiable, so failing here degrades
/// nothing.
async fn rotate_jwt_authority_if_due(ca: &SharedCa) -> Option<u64> {
    let signer = ca.jwt_signer()?;
    match signer.rotate_if_due().await {
        Ok(generation) => generation,
        Err(e) => {
            warn!(error = %e, "JWT-SVID signing key rotation failed; keeping the current key");
            None
        }
    }
}

fn bump_revision(revision_tx: &watch::Sender<u64>) -> u64 {
    revision_tx.send_modify(|revision| *revision = revision.saturating_add(1));
    *revision_tx.borrow()
}

async fn mint_and_install(config: &RotationConfig) -> Result<(), String> {
    let svid = config
        .ca
        .issue_svid(IssuanceRequest::Generate {
            spiffe_id: config.spiffe_id.clone(),
            ttl_secs: config.svid_ttl_secs,
        })
        .await
        .map_err(|e| e.to_string())?;
    let bundle = config
        .ca
        .trust_bundle(config.spiffe_id.trust_domain())
        .await
        .map_err(|e| e.to_string())?;
    crate::plugins::mesh::prometheus_helpers::record_mesh_cert_expiry_at(
        &svid.spiffe_id,
        "rotation",
        &svid.not_after,
    );
    crate::plugins::mesh::prometheus_helpers::record_mesh_trust_bundle(&bundle, "rotation");

    // JWT authorities are best-effort here: a backend that publishes none
    // (SPIRE agent today) leaves the list empty, and an X.509 SVID must still
    // install. The Workload API reads authorities from the CA directly, so
    // this list is a convenience for consumers of `SvidBundle`, not the
    // source of truth for `FetchJWTBundles`.
    let jwt_authorities = match config
        .ca
        .jwt_authorities(config.spiffe_id.trust_domain())
        .await
    {
        Ok(published) => published
            .into_iter()
            .map(|authority| crate::identity::JwtAuthority {
                key_id: authority.key_id,
                public_key_pem: authority.public_key_pem,
            })
            .collect(),
        Err(e) => {
            debug!(error = %e, "rotation: no JWT authorities published for this trust domain");
            Vec::new()
        }
    };

    let svid_bundle = SvidBundle {
        spiffe_id: svid.spiffe_id.clone(),
        cert_chain_der: svid.cert_chain_der,
        private_key_pkcs8_der: svid.private_key_pkcs8_der,
        trust_bundles: TrustBundleSet {
            local: TrustBundle {
                trust_domain: bundle.trust_domain.clone(),
                x509_authorities: bundle.roots_der.clone(),
                jwt_authorities,
                refresh_hint_seconds: bundle.refresh_hint_secs,
            },
            federated: Default::default(),
        },
    };
    debug!(spiffe_id = %svid.spiffe_id, "rotation: minted fresh SVID");
    config.current.store(Arc::new(Some(svid_bundle)));
    Ok(())
}

/// Inspect the leaf certificate of a bundle and decide how long to sleep
/// before checking rotation again. The result is bounded by
/// [`MIN_TICK`]/[`MAX_TICK`].
pub fn decide_next_tick(bundle: &SvidBundle, rotate_at_fraction: f64) -> Duration {
    let (not_before, not_after) = match leaf_validity(bundle) {
        Some(v) => v,
        None => return MIN_TICK,
    };
    let total = (not_after - not_before).num_seconds().max(1);
    let rotate_at =
        not_before + chrono::Duration::seconds((total as f64 * rotate_at_fraction) as i64);
    let now = Utc::now();
    let until_rotate = (rotate_at - now).num_seconds();
    let next_tick = if until_rotate <= 0 {
        MIN_TICK
    } else {
        Duration::from_secs(until_rotate as u64)
    };
    next_tick.clamp(MIN_TICK, MAX_TICK)
}

/// `true` iff the bundle's leaf is past its rotation threshold.
pub fn is_due_for_rotation(bundle: &SvidBundle, rotate_at_fraction: f64) -> bool {
    let (not_before, not_after) = match leaf_validity(bundle) {
        Some(v) => v,
        None => return true,
    };
    let total = (not_after - not_before).num_seconds().max(1);
    let rotate_at =
        not_before + chrono::Duration::seconds((total as f64 * rotate_at_fraction) as i64);
    Utc::now() >= rotate_at
}

fn leaf_validity(bundle: &SvidBundle) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let leaf = bundle.cert_chain_der.first()?;
    let (_, parsed) = X509Certificate::from_der(leaf).ok()?;
    let validity = parsed.validity();
    let not_before = DateTime::<Utc>::from_timestamp(validity.not_before.timestamp(), 0)?;
    let not_after = DateTime::<Utc>::from_timestamp(validity.not_after.timestamp(), 0)?;
    Some((not_before, not_after))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_revision_notifies_watch_subscribers() {
        let (revision_tx, mut revision_rx) = watch::channel(0u64);

        assert_eq!(*revision_rx.borrow(), 0);
        assert_eq!(bump_revision(&revision_tx), 1);
        assert!(revision_rx.has_changed().expect("watch sender is alive"));
        assert_eq!(*revision_rx.borrow_and_update(), 1);

        assert_eq!(bump_revision(&revision_tx), 2);
        assert!(revision_rx.has_changed().expect("watch sender is alive"));
        assert_eq!(*revision_rx.borrow_and_update(), 2);
    }
}
