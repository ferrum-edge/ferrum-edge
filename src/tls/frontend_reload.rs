//! Opt-in frontend TLS cert/key live reload.
//!
//! Default behavior remains static: cert/key files are read once at startup and
//! rotation requires a restart. When `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`,
//! a background poll task watches the configured TLS material sources for the
//! proxy HTTPS / H2 / H3 listeners and (separately) the admin HTTPS listener.
//! On any material fingerprint change, the task rebuilds the
//! `rustls::ServerConfig` using the caller-supplied closure and atomically
//! swaps it into the shared `SharedFrontendTls` slot. A failed validation
//! (parse / expired / not-yet-valid / key mismatch / closure error) keeps the
//! previous config and emits a `warn!` — the gateway never serves a known-bad
//! TLS config from this path.
//!
//! In-flight TLS sessions keep their original `ServerConfig` clone (rustls
//! consults the config only during handshake). Cert/key-only and additive trust
//! rotations leave those sessions running; an accepted client-trust narrowing
//! separately retires client-certificate-authenticated sessions through
//! [`crate::tls::client_trust`]. Only newly accepted connections handshake
//! against the new config.
//!
//! The H3 / QUIC listener observes swaps through the same slot via a
//! [`tokio::sync::watch`] revision counter; the H3 task rebuilds its
//! [`quinn::ServerConfig`] and applies it with
//! [`quinn::Endpoint::set_server_config`]. Existing QUIC connections keep
//! serving unless an accepted client-trust narrowing retires their scope.
//!
//! Frontend DTLS (UDP) material is live-reloaded under the same opt-in flag by
//! [`crate::proxy::ProxyState`]'s DTLS source watcher: it validates one
//! immutable generation (server cert/key, optional client CA, CRLs) and
//! publishes it into every active `DtlsServer` without rebinding. Backend
//! client TLS and per-proxy `backend_tls_client_cert_path` remain outside this
//! module — backend SVID rotation lives in [`crate::proxy`] under the
//! `gateway_svid_*` watch.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use rustls::ServerConfig;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::tls::source::subscription::{
    MaterialSetReloadConfig, WatchedMaterialSource, spawn_material_set_reload_task,
};

/// Shared frontend `ServerConfig` slot. Listeners load this on each new
/// connection, so a swap takes effect on the next handshake without touching
/// in-flight TLS sessions.
pub type SharedFrontendTls = Arc<ArcSwap<Option<Arc<ServerConfig>>>>;

/// Construct an empty `SharedFrontendTls` slot (no TLS configured). This is
/// the default for plaintext-only listeners and for instances that have not
/// loaded TLS at startup.
pub fn empty_frontend_tls_slot() -> SharedFrontendTls {
    Arc::new(ArcSwap::new(Arc::new(None)))
}

/// Build a `SharedFrontendTls` slot pre-populated with the startup-loaded
/// `Arc<ServerConfig>`.
pub fn frontend_tls_slot_with(initial: Arc<ServerConfig>) -> SharedFrontendTls {
    Arc::new(ArcSwap::new(Arc::new(Some(initial))))
}

/// One accepted frontend TLS publication, as a single indivisible value
/// (issue #3857).
///
/// A listener family that applies a reload **asynchronously** — the QUIC/HTTP-3
/// endpoint is the only one — cannot reconstruct the accepted generation from
/// parts. Reading the `ServerConfig` from one slot, re-reading the client-CA
/// source, reusing a startup CRL clone, and then fetching "the latest" trust
/// material from another scope gives four values from four instants: the
/// verifier it installs and the generation it publishes can describe different
/// material, and coalesced revisions make it worse. Everything such a consumer
/// needs is therefore published here as one `Arc`, taken with one atomic load.
pub struct AcceptedFrontendTls {
    /// The `ServerConfig` swapped into the plain slot for this same candidate,
    /// including the surface's post-load opt-ins.
    pub config: Arc<ServerConfig>,
    /// The client-certificate verifier compiled into `config`, paired with the
    /// semantic identity of the exact client-CA bytes and CRLs behind it.
    pub client_trust: crate::tls::AcceptedClientTrust,
}

/// Shared accepted-candidate slot. Published by the reload task and consumed by
/// the HTTP/3 listener, which applies its config out of band.
pub type SharedAcceptedFrontendTls = Arc<ArcSwap<Option<Arc<AcceptedFrontendTls>>>>;

/// Build a `SharedAcceptedFrontendTls` slot pre-populated with the
/// startup-accepted candidate.
pub fn accepted_frontend_tls_slot_with(
    initial: Arc<AcceptedFrontendTls>,
) -> SharedAcceptedFrontendTls {
    Arc::new(ArcSwap::new(Arc::new(Some(initial))))
}

/// Build an empty `SharedAcceptedFrontendTls` slot.
///
/// A data plane whose only frontend server certificate is control-plane
/// delivered owns accepted client trust before it owns any server certificate
/// (issue #3857). It publishes that trust immediately, but there is no
/// candidate for the HTTP/3 endpoint to adopt until CP material arrives — and
/// synthesizing an operator server certificate to fill the slot is exactly what
/// must not happen. An empty slot disables the endpoint fail-closed instead.
pub fn empty_accepted_frontend_tls_slot() -> SharedAcceptedFrontendTls {
    Arc::new(ArcSwap::new(Arc::new(None)))
}

/// Configuration for [`spawn_frontend_tls_reload_task`].
pub struct FrontendTlsReloadConfig {
    /// Human-readable identifier for logs ("proxy https", "admin https",
    /// "mesh inbound"). Surfaces emit a Prometheus label off this name when
    /// metrics are wired up.
    pub surface: &'static str,
    /// TLS material sources whose fingerprint changes should trigger a rebuild.
    pub sources: Vec<WatchedMaterialSource>,
    /// Live `SharedFrontendTls` slot the watcher swaps on a validated change.
    pub slot: SharedFrontendTls,
    /// Poll interval; clamp at 1s upstream of this function.
    pub interval: Duration,
    /// Revision sender. Subscribers (e.g., the H3 listener) observe `.changed()`
    /// to rebuild listener-specific TLS material (e.g., `QuicServerConfig`) and
    /// apply it with `Endpoint::set_server_config`. The watcher bumps this
    /// after a successful swap; the value is the rotation generation.
    pub revision_tx: watch::Sender<u64>,
    /// Validated TLS material byte ceiling for source loads.
    pub max_material_bytes: usize,
    /// Closure invoked on every change to rebuild the `ServerConfig`.
    /// The closure is responsible for the surface-specific options that
    /// startup applied (ALPN advertisement, early-data, kTLS opt-in, client
    /// CA verification, session tickets). A returned `Err` keeps the previous
    /// config and emits a `warn!`.
    pub rebuild: FrontendTlsRebuildFn,
    /// Client-trust scope this rustls listener family owns (issue #3857).
    /// One rustls listener family owns exactly one scope. When `Some`, a
    /// successful rebuild executes exactly one verifier -> config exposure ->
    /// material/generation/fence transaction under that scope's lock. When
    /// `None`, the task performs ordinary slot publication with no trust
    /// generation. A refused candidate is recorded against that singular
    /// scope while the last accepted generation, verifier and sessions are
    /// all retained.
    ///
    /// HTTP/3 remains independently owned and published by `ProxyH3`
    /// (`http3::server`); it is never listed here even when
    /// [`accepted_slot`](Self::accepted_slot) is populated for H3 to adopt.
    pub client_trust_scope: Option<crate::tls::ClientTrustScope>,
    /// Optional accepted-candidate slot for a consumer that applies the reload
    /// asynchronously (the HTTP/3 endpoint). The task republishes the whole
    /// [`AcceptedFrontendTls`] here on every accepted candidate, so that
    /// consumer never has to reassemble one from independently read parts.
    pub accepted_slot: Option<SharedAcceptedFrontendTls>,
}

/// One accepted frontend TLS candidate.
///
/// Carries the client-certificate verifier and semantic client-trust identity
/// alongside the rebuilt `ServerConfig` so the generation published for an
/// established transport can never describe material other than the material
/// actually swapped in. Deriving either by re-reading the sources after the
/// swap would race the next rotation.
pub struct FrontendTlsRebuilt {
    /// The rebuilt server configuration to publish into the slot.
    pub config: Arc<ServerConfig>,
    /// Verifier + semantic client-CA / CRL identity of this same candidate.
    /// `None` when the surface does not participate in client-trust
    /// generations.
    pub client_trust: Option<crate::tls::AcceptedClientTrust>,
}

/// Surface-specific rebuild closure.
pub type FrontendTlsRebuildFn =
    Box<dyn Fn() -> Result<FrontendTlsRebuilt, anyhow::Error> + Send + Sync + 'static>;

/// Spawn the frontend TLS file-watch task.
///
/// The task polls `interval` and, on every detected file change, calls
/// `rebuild` and either swaps the resulting config into `slot` (success) or
/// keeps the previous config and logs a `warn!` (failure). The first failing
/// fingerprint after a successful state is remembered so the watcher does not
/// re-warn on every poll while a bad state is stable.
///
/// The handle exits cleanly when the shutdown receiver fires.
pub fn spawn_frontend_tls_reload_task(
    config: FrontendTlsReloadConfig,
    shutdown_rx: Option<watch::Receiver<bool>>,
) -> JoinHandle<()> {
    let FrontendTlsReloadConfig {
        surface,
        sources,
        slot,
        interval,
        revision_tx,
        max_material_bytes,
        rebuild,
        client_trust_scope,
        accepted_slot,
    } = config;

    let publish_rebuild = Box::new(move || {
        let rebuilt = match rebuild() {
            Ok(rebuilt) => rebuilt,
            Err(error) => {
                // A refused candidate keeps the last-good verifier, generation
                // and every live session — including the HTTP/3 endpoint's,
                // whose accepted slot is left untouched here. Recording it (
                // rather than at the load site) is what makes "retained, not
                // silently ignored" observable on the singular scope.
                if let Some(scope) = client_trust_scope {
                    crate::tls::client_trust::record_rejected_candidate(scope);
                }
                return Err(error);
            }
        };
        let FrontendTlsRebuilt {
            config: new_config,
            client_trust,
        } = rebuilt;
        // A surface whose scope is armed performs verified client-certificate
        // authentication, and that mode is fixed configuration: the client-CA
        // source and the `*_NO_VERIFY` switch are read once at startup and are
        // not part of what live reload may change. A rebuilt candidate carrying
        // no verifier would therefore be a silent authentication-mode change,
        // and publishing its (empty) identity would read as a total client-CA
        // withdrawal. Refuse the candidate instead and retain the complete
        // last-good generation, verifier and sessions (issue #3857).
        if let Some(scope) = client_trust_scope
            && client_trust
                .as_ref()
                .is_none_or(|client_trust| client_trust.verifier.is_none())
        {
            crate::tls::client_trust::record_rejected_candidate(scope);
            return Err(anyhow::anyhow!(
                "frontend TLS reload candidate performs no client-certificate authentication on a \
                 surface configured for it; keeping the previous configuration"
            ));
        }
        // Every fallible rebuild/validation step has succeeded. When this
        // listener family owns a scope, exactly one rustls transaction holds
        // the publication lock across: install the live verifier, expose this
        // candidate's ServerConfig (and the H3 accepted slot), then publish
        // material/generation/fence. No scope means ordinary slot publication.
        // A refused candidate never reaches this store.
        if let Some(scope) = client_trust_scope
            && let Some(client_trust) = client_trust.as_ref()
            && let Some(verifier) = client_trust.verifier.clone()
        {
            let publication = crate::tls::client_trust::publish_accepted_rustls_candidate(
                scope,
                client_trust.material.clone(),
                verifier,
                || {
                    if let Some(accepted_slot) = accepted_slot.as_ref() {
                        accepted_slot.store(Arc::new(Some(Arc::new(AcceptedFrontendTls {
                            config: new_config.clone(),
                            client_trust: client_trust.clone(),
                        }))));
                    }
                    slot.store(Arc::new(Some(new_config.clone())));
                },
            );
            if publication.withdrew() {
                tracing::warn!(
                    scope = publication.scope.label(),
                    generation = publication.generation,
                    reason = publication.reason.map(|reason| reason.label()),
                    retired_connections = publication.retired_sessions,
                    "Frontend client-certificate trust was withdrawn; established client-certificate transports on this scope were retired"
                );
            }
        } else {
            if let (Some(accepted_slot), Some(client_trust)) =
                (accepted_slot.as_ref(), client_trust.as_ref())
            {
                accepted_slot.store(Arc::new(Some(Arc::new(AcceptedFrontendTls {
                    config: new_config.clone(),
                    client_trust: client_trust.clone(),
                }))));
            }
            slot.store(Arc::new(Some(new_config)));
        }
        Ok(())
    });

    spawn_material_set_reload_task(
        MaterialSetReloadConfig {
            surface,
            sources,
            interval,
            revision_tx,
            rebuild: publish_rebuild,
            max_material_bytes,
            ready_tx: None,
        },
        shutdown_rx,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn empty_slot_has_none_inside() {
        let slot = empty_frontend_tls_slot();
        assert!(slot.load().is_none());
    }

    #[tokio::test]
    async fn reload_task_swaps_on_change_and_keeps_old_on_failure() {
        use crate::fips::base_crypto_provider as default_provider;
        use crate::tls::source::{CertSource, MaterialKind};
        let _ = default_provider().install_default();

        // Build a placeholder initial config so the slot holds Some(..).
        let initial = build_dummy_server_config();
        let slot = frontend_tls_slot_with(initial.clone());

        let dir = tempfile::tempdir().expect("tempdir");
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, b"placeholder cert").expect("write cert");
        std::fs::write(&key, b"placeholder key").expect("write key");

        // Use an atomic mode flag: on first attempt return Ok with a fresh
        // ServerConfig; on second attempt return Err to simulate a bad
        // rotation. Verify the slot keeps the old config after the failure.
        let attempts = Arc::new(AtomicUsize::new(0));
        let success_config = build_dummy_server_config();

        let attempts_clone = attempts.clone();
        let success_clone = success_config.clone();
        let rebuild: FrontendTlsRebuildFn = Box::new(move || {
            let attempt = attempts_clone.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                Ok(FrontendTlsRebuilt {
                    config: success_clone.clone(),
                    client_trust: None,
                })
            } else {
                Err(anyhow::anyhow!("simulated cert expired"))
            }
        });

        let (revision_tx, mut revision_rx) = watch::channel(0u64);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = spawn_frontend_tls_reload_task(
            FrontendTlsReloadConfig {
                // Unique surface per test: the force-reload registry is a
                // process-global keyed by surface, so a shared name lets a
                // parallel test's task drop this one's force sender and exit
                // early (`cargo test --lib` runs tests concurrently).
                surface: "test_frontend_reload_swap",
                max_material_bytes: crate::config::env_config::DEFAULT_TLS_MAX_MATERIAL_SIZE_BYTES,
                sources: vec![
                    WatchedMaterialSource::new(
                        "cert",
                        CertSource::parse(cert.to_string_lossy().into_owned(), MaterialKind::Cert),
                        MaterialKind::Cert,
                    ),
                    WatchedMaterialSource::new(
                        "key",
                        CertSource::parse(key.to_string_lossy().into_owned(), MaterialKind::Key),
                        MaterialKind::Key,
                    ),
                ],
                slot: slot.clone(),
                interval: Duration::from_millis(50),
                revision_tx,
                rebuild,
                client_trust_scope: None,
                accepted_slot: None,
            },
            Some(shutdown_rx),
        );

        // Wait for fingerprint to take, then bump the cert to trigger the
        // first rebuild (success).
        tokio::time::sleep(Duration::from_millis(80)).await;
        std::thread::sleep(Duration::from_millis(10));
        std::fs::write(&cert, b"new cert bytes one").expect("rewrite cert");

        // Wait for the watcher to apply the swap + bump the revision.
        tokio::time::timeout(Duration::from_secs(2), revision_rx.changed())
            .await
            .expect("revision should bump after successful reload")
            .expect("watcher should still be alive");
        assert_eq!(*revision_rx.borrow(), 1);

        let after_success = slot.load_full().as_ref().clone();
        assert!(after_success.is_some(), "slot should still hold a config");
        let after_success_arc = after_success.unwrap();
        assert!(
            Arc::ptr_eq(&after_success_arc, &success_config),
            "successful reload should swap in the rebuilt config"
        );

        // Now flip the cert again — the rebuild closure returns Err this time.
        std::thread::sleep(Duration::from_millis(10));
        std::fs::write(&cert, b"new cert bytes two").expect("rewrite cert");

        // Give the watcher a few ticks to observe + reject.
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Revision should NOT have bumped past 1.
        assert_eq!(*revision_rx.borrow(), 1, "failed reload must not bump");

        // Slot should still hold the previously-successful config.
        let after_failure = slot.load_full().as_ref().clone().expect("slot intact");
        assert!(
            Arc::ptr_eq(&after_failure, &success_config),
            "failed reload must keep the previously-successful config"
        );

        task.abort();
    }

    fn build_dummy_server_config() -> Arc<ServerConfig> {
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let cert = params.self_signed(&key_pair).expect("self-sign cert");

        let cert_pem = cert.pem();
        let certs: Vec<_> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .filter_map(Result::ok)
            .collect();
        let key_pem = key_pair.serialize_pem();
        let private_key =
            PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("read private key");

        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                crate::fips::base_crypto_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .expect("server cert"),
        )
    }
}
