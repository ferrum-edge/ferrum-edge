//! Mode-side helpers to wire opt-in frontend TLS live reload into the proxy
//! and admin HTTPS listeners.
//!
//! Default `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=false` keeps today's
//! static-input behavior: [`prepare_proxy_frontend_tls`] /
//! [`prepare_admin_frontend_tls`] return only the loaded config and no
//! watcher.  When the operator opts in, the helpers additionally build a
//! `SharedFrontendTls` slot pre-populated with the loaded config and spawn a
//! poll task that re-runs the same load (`load_tls_config_with_client_auth`
//! plus the surface-specific post-load options) on watched source changes,
//! atomically swapping the slot on success and warning-and-keeping the old
//! slot on validation failure.
//!
//! The proxy H3 listener subscribes to the proxy slot's revision channel so
//! it can rebuild the `quinn::ServerConfig` after a swap; see
//! [`crate::http3::server::Http3FrontendTlsReload`].

use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt as _;
use rustls::ServerConfig;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::EnvConfig;
use crate::tls::client_trust::{self, ClientTrustScope};
use crate::tls::source::subscription::{
    AsyncMaterialSetReloadConfig, WatchedMaterialSource, material_set_poll_interval,
    source_is_refreshable, spawn_async_material_set_reload_task_with_startup_reconcile,
};
use crate::tls::source::{CertSource, MaterialKind};
use crate::tls::{
    self, AcceptedClientTrust, AcceptedFrontendTls, CrlList, FrontendTlsRebuildFn,
    FrontendTlsRebuilt, FrontendTlsReloadConfig, SharedAcceptedFrontendTls, SharedFrontendTls,
    TlsPolicy, empty_frontend_tls_slot, spawn_frontend_tls_reload_task,
};

/// Result of wiring the proxy frontend TLS live-reload path. When live reload
/// is disabled (the default) every field is `None`; the caller continues
/// using the startup-loaded `Arc<rustls::ServerConfig>` directly.
pub struct ProxyFrontendTlsReloadHandles {
    /// Pre-populated shared slot the HTTPS / H2 listeners load on each
    /// accept. `Some` only when live reload is enabled.
    pub slot: Option<SharedFrontendTls>,
    /// Pre-populated accepted-candidate slot the H3 listener adopts wholesale
    /// (issue #3857). `Some` only when live reload is enabled **and** the
    /// startup candidate's client-trust identity is known, because a partial
    /// snapshot is exactly what this slot exists to prevent. DP mode does not
    /// feed this slot to H3 directly: it copies each accepted operator
    /// candidate into a pairing slot so HTTP/3 can keep a CP-delivered server
    /// certificate while still enforcing this operator trust identity.
    pub accepted_slot: Option<SharedAcceptedFrontendTls>,
    /// Subscribe-able revision channel the H3 listener observes. `Some` only
    /// when live reload is enabled.
    pub revision_rx: Option<watch::Receiver<u64>>,
    /// Handle to the spawned watcher task. `Some` only when live reload is
    /// enabled. The watcher self-terminates when the shutdown receiver it
    /// holds fires, so callers may safely detach this handle by dropping it
    /// — the task will exit on its own at gateway shutdown.
    pub watcher_handle: Option<JoinHandle<()>>,
}

/// Build the proxy frontend TLS slot + reload watcher, applying the proxy-
/// frontend-specific post-load options (`enable_early_data`, optional kTLS
/// secret-extraction opt-in).
///
/// The rebuild closure mirrors the startup path:
/// `load_tls_config_with_client_auth(cert, key, client_ca, no_verify, policy,
/// warning_days, crls)` followed by the same `enable_early_data` /
/// `enable_secret_extraction_for_ktls` opt-ins.  Validation failures (parse,
/// expired, not-yet-valid, key mismatch) flow out as the closure's `Err` and
/// keep the previous config — never serving a known-bad TLS config.
pub fn prepare_proxy_frontend_tls(
    tls_config: Arc<ServerConfig>,
    startup_client_trust: Option<AcceptedClientTrust>,
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &CrlList,
    shutdown_rx: Option<watch::Receiver<bool>>,
) -> ProxyFrontendTlsReloadHandles {
    if !env_config.frontend_tls_live_reload_enabled {
        return ProxyFrontendTlsReloadHandles {
            slot: None,
            accepted_slot: None,
            revision_rx: None,
            watcher_handle: None,
        };
    }

    let (Some(cert_path), Some(key_path)) = (
        env_config.frontend_tls_cert_path.clone(),
        env_config.frontend_tls_key_path.clone(),
    ) else {
        // Live reload requested but no cert/key configured — defensive
        // no-op. The caller's listener startup path would have already
        // skipped HTTPS for the same reason.
        info!(
            "FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true but no frontend cert/key configured; live reload disabled"
        );
        return ProxyFrontendTlsReloadHandles {
            slot: None,
            accepted_slot: None,
            revision_rx: None,
            watcher_handle: None,
        };
    };
    let cert_source = CertSource::parse(cert_path, MaterialKind::Cert);
    let key_source = CertSource::parse(key_path, MaterialKind::Key);
    let client_ca_source = env_config
        .frontend_tls_client_ca_bundle_path
        .clone()
        .map(|source| CertSource::parse(source, MaterialKind::CaBundle));
    let ocsp_source = env_config
        .frontend_tls_ocsp_response_source
        .clone()
        .map(|source| CertSource::parse(source, MaterialKind::Ocsp));
    let crl_source = env_config
        .tls_crl_file_path
        .clone()
        .map(|source| CertSource::parse(source, MaterialKind::Crl));
    let watched_sources = frontend_watched_sources(
        &cert_source,
        &key_source,
        client_ca_source.as_ref(),
        ocsp_source.as_ref(),
        crl_source.as_ref(),
    );
    if !watched_sources
        .iter()
        .any(|source| source_is_refreshable(&source.source))
    {
        info!(
            "FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true but frontend TLS sources are static inline material; live reload disabled for proxy HTTPS"
        );
        return ProxyFrontendTlsReloadHandles {
            slot: None,
            accepted_slot: None,
            revision_rx: None,
            watcher_handle: None,
        };
    };

    // Arm this listener family's client-trust generation from the material the
    // caller's `tls_config` was ACTUALLY built from (issue #3857). One rustls
    // transaction installs the live verifier, exposes the slot, then publishes
    // generation. Until a scope is armed, `client_trust::capture` returns
    // `None` and the accept paths pay nothing — which is exactly the default,
    // live-reload disabled posture. Arming here (rather than lazily on the first
    // reload) means the very first accepted connection already carries a
    // generation the first reload can fence it against.
    //
    // `startup_client_trust` must come from the same load that produced
    // `tls_config`; re-reading the client-CA source here to summarize it would
    // observe whatever the file holds *now*. A source narrowed between the
    // startup load and that read would be recorded as the baseline while the
    // wider set is what is being served, so the first real withdrawal compares
    // equal to the baseline, publishes `Unchanged`, and never retires anything.
    //
    // Only the HTTPS/H2 + TCP+TLS family is armed here. The H3 endpoint owns
    // `ProxyH3` and arms it from the exact verifier it installs on its own
    // endpoint, because it applies a reload asynchronously.
    //
    // A scope is armed ONLY when the exact accepted candidate actually performs
    // verified client-certificate authentication (issue #3857). No client-CA
    // source (`FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH`) means no transport
    // on this listener can ever hold a credential a CRL or client-CA
    // withdrawal could revoke: arming it would publish an empty baseline, export
    // retirement metrics for a protection with nothing to protect, and make
    // `client_trust::capture` return `Some` on every accept — which is what
    // made TCP+TLS decline the kTLS fast path on listeners that do no client
    // authentication at all. Certificate/key-only rotation is unaffected; it
    // simply reloads without a trust generation.
    let client_trust_scope = match startup_client_trust.as_ref() {
        Some(startup_client_trust) if startup_client_trust.verifier.is_some() => {
            Some(ClientTrustScope::ProxyFrontend)
        }
        Some(_) => {
            info!(
                "Proxy frontend TLS live reload is enabled without verified client-certificate authentication; the proxy client-trust scope stays unarmed"
            );
            None
        }
        None => {
            warn!(
                "Frontend TLS live reload is enabled but the caller supplied no startup client-CA/CRL identity for the served TLS configuration; established-transport trust retirement is disabled for proxy HTTPS"
            );
            None
        }
    };
    // The H3 endpoint adopts whole accepted candidates. A startup candidate
    // whose trust identity is unknown cannot form one, so the slot stays absent
    // and the H3 listener falls back to its own coherent load rather than
    // pairing a config with an identity that did not come from it.
    let accepted_slot = startup_client_trust.as_ref().map(|_| {
        Arc::new(arc_swap::ArcSwap::from_pointee(
            None::<Arc<AcceptedFrontendTls>>,
        ))
    });

    let slot = empty_frontend_tls_slot();
    if let Some(scope) = client_trust_scope
        && let Some(startup_client_trust) = startup_client_trust.as_ref()
        && let Some(verifier) = startup_client_trust.verifier.clone()
    {
        client_trust::publish_accepted_rustls_candidate(
            scope,
            startup_client_trust.material.clone(),
            verifier,
            || {
                if let Some(accepted_slot) = accepted_slot.as_ref() {
                    accepted_slot.store(Arc::new(Some(Arc::new(AcceptedFrontendTls {
                        config: tls_config.clone(),
                        client_trust: startup_client_trust.clone(),
                    }))));
                }
                slot.store(Arc::new(Some(tls_config.clone())));
            },
        );
    } else {
        if let Some(accepted_slot) = accepted_slot.as_ref()
            && let Some(startup_client_trust) = startup_client_trust.as_ref()
        {
            accepted_slot.store(Arc::new(Some(Arc::new(AcceptedFrontendTls {
                config: tls_config.clone(),
                client_trust: startup_client_trust.clone(),
            }))));
        }
        slot.store(Arc::new(Some(tls_config.clone())));
    }
    let (revision_tx, revision_rx) = watch::channel(0u64);
    let interval = material_set_poll_interval(
        &watched_sources,
        Duration::from_secs(env_config.frontend_tls_watch_interval_seconds.max(1)),
        Duration::from_secs(env_config.secret_refresh_interval_seconds.max(1)),
    );

    let rebuild = build_proxy_rebuild_fn(
        env_config,
        tls_policy,
        crls,
        cert_source,
        key_source,
        client_ca_source,
        ocsp_source,
        env_config.tls_crl_file_path.clone(),
    );

    let handle = spawn_frontend_tls_reload_task(
        FrontendTlsReloadConfig {
            surface: "proxy_https",
            sources: watched_sources,
            slot: slot.clone(),
            interval,
            revision_tx,
            rebuild,
            max_material_bytes: env_config.tls_max_material_size_bytes,
            client_trust_scope,
            accepted_slot: accepted_slot.clone(),
        },
        shutdown_rx,
    );

    ProxyFrontendTlsReloadHandles {
        slot: Some(slot),
        accepted_slot,
        revision_rx: Some(revision_rx),
        watcher_handle: Some(handle),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_proxy_rebuild_fn(
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &CrlList,
    cert_source: CertSource,
    key_source: CertSource,
    client_ca_source: Option<CertSource>,
    ocsp_source: Option<CertSource>,
    crl_source_value: Option<String>,
) -> FrontendTlsRebuildFn {
    let warning_days = env_config.tls_cert_expiry_warning_days;
    let revocation_warning_days = env_config.tls_crl_expiry_warning_days;
    let ktls_could_be_enabled = env_config.ktls_enabled.could_be_enabled();
    let policy = tls_policy.clone();
    let startup_crls = crls.clone();

    Box::new(move || -> Result<FrontendTlsRebuilt, anyhow::Error> {
        let active_crls = match crl_source_value.as_deref() {
            Some(source) => tls::load_crls(Some(source), revocation_warning_days)?,
            None => startup_crls.clone(),
        };
        let candidate = tls::load_frontend_tls_candidate(
            &cert_source,
            &key_source,
            client_ca_source.as_ref(),
            ocsp_source.as_ref(),
            false,
            &policy,
            warning_days,
            revocation_warning_days,
            &active_crls,
            Some(ClientTrustScope::ProxyFrontend),
        )?;
        let mut config = candidate.config;
        // Reapply the proxy-frontend-specific opt-ins so rotated configs
        // match startup semantics (0-RTT, kTLS secret extraction).
        tls::enable_early_data(&mut config, &policy);
        if ktls_could_be_enabled {
            tls::enable_secret_extraction_for_ktls(&mut config);
        }
        Ok(FrontendTlsRebuilt {
            config,
            client_trust: Some(candidate.client_trust),
        })
    })
}

/// Whether the proxy frontend live-reload path can arm the `ProxyFrontend`
/// client-trust scope for THIS configuration (issue #3857).
///
/// [`prepare_proxy_frontend_tls`] returns unarmed on three configuration
/// predicates before it ever looks at the accepted candidate: the process-wide
/// opt-in, a configured cert/key pair, and at least one watched source that is
/// actually refreshable (an all-inline-PEM configuration is static, so no
/// generation can ever be published for it). This is exactly those three, kept
/// in one place so `modes::startup_security::proxy_frontend_handshake_scope`
/// cannot install the live handshake wrapper — and with it empty
/// CertificateRequest CA-name hints for TLS 1.2 clients — on a listener where
/// nothing will ever be armed.
///
/// The fourth predicate `prepare_proxy_frontend_tls` applies (the accepted
/// candidate performs verified client-certificate authentication) is
/// deliberately NOT modelled here: it needs the candidate, which does not exist
/// yet when the `ServerConfig` is being built. It is also harmless to omit —
/// with no client-certificate verifier the listener sends no CertificateRequest
/// at all, so there are no CA-name hints to lose and no mTLS resumption to
/// suppress.
pub fn proxy_frontend_live_reload_can_arm(env_config: &EnvConfig) -> bool {
    if !env_config.frontend_tls_live_reload_enabled {
        return false;
    }
    let (Some(cert_path), Some(key_path)) = (
        env_config.frontend_tls_cert_path.clone(),
        env_config.frontend_tls_key_path.clone(),
    ) else {
        return false;
    };
    let cert_source = CertSource::parse(cert_path, MaterialKind::Cert);
    let key_source = CertSource::parse(key_path, MaterialKind::Key);
    let client_ca_source = env_config
        .frontend_tls_client_ca_bundle_path
        .clone()
        .map(|source| CertSource::parse(source, MaterialKind::CaBundle));
    let ocsp_source = env_config
        .frontend_tls_ocsp_response_source
        .clone()
        .map(|source| CertSource::parse(source, MaterialKind::Ocsp));
    let crl_source = env_config
        .tls_crl_file_path
        .clone()
        .map(|source| CertSource::parse(source, MaterialKind::Crl));
    frontend_watched_sources(
        &cert_source,
        &key_source,
        client_ca_source.as_ref(),
        ocsp_source.as_ref(),
        crl_source.as_ref(),
    )
    .iter()
    .any(|source| source_is_refreshable(&source.source))
}

/// [`proxy_frontend_live_reload_can_arm`] for the admin HTTPS listener. Same
/// three configuration predicates over the `FERRUM_ADMIN_TLS_*` sources, so
/// `modes::startup_security::admin_https_handshake_scope` and
/// [`prepare_admin_frontend_tls`] cannot disagree about whether the `AdminHttps`
/// scope can ever be armed.
pub fn admin_frontend_live_reload_can_arm(env_config: &EnvConfig) -> bool {
    if !env_config.frontend_tls_live_reload_enabled {
        return false;
    }
    let (Some(cert_path), Some(key_path)) = (
        env_config.admin_tls_cert_path.clone(),
        env_config.admin_tls_key_path.clone(),
    ) else {
        return false;
    };
    let cert_source = CertSource::parse(cert_path, MaterialKind::Cert);
    let key_source = CertSource::parse(key_path, MaterialKind::Key);
    let client_ca_source = env_config
        .admin_tls_client_ca_bundle_path
        .clone()
        .map(|source| CertSource::parse(source, MaterialKind::CaBundle));
    let ocsp_source = env_config
        .admin_tls_ocsp_response_source
        .clone()
        .map(|source| CertSource::parse(source, MaterialKind::Ocsp));
    let crl_source = env_config
        .tls_crl_file_path
        .clone()
        .map(|source| CertSource::parse(source, MaterialKind::Crl));
    frontend_watched_sources(
        &cert_source,
        &key_source,
        client_ca_source.as_ref(),
        ocsp_source.as_ref(),
        crl_source.as_ref(),
    )
    .iter()
    .any(|source| source_is_refreshable(&source.source))
}

fn frontend_watched_sources(
    cert_source: &CertSource,
    key_source: &CertSource,
    client_ca_source: Option<&CertSource>,
    ocsp_source: Option<&CertSource>,
    crl_source: Option<&CertSource>,
) -> Vec<WatchedMaterialSource> {
    let mut sources = vec![
        WatchedMaterialSource::new("cert", cert_source.clone(), MaterialKind::Cert),
        WatchedMaterialSource::new("key", key_source.clone(), MaterialKind::Key),
    ];
    if let Some(client_ca_source) = client_ca_source {
        sources.push(WatchedMaterialSource::new(
            "client_ca",
            client_ca_source.clone(),
            MaterialKind::CaBundle,
        ));
    }
    if let Some(ocsp_source) = ocsp_source {
        sources.push(WatchedMaterialSource::new(
            "ocsp",
            ocsp_source.clone(),
            MaterialKind::Ocsp,
        ));
    }
    if let Some(crl_source) = crl_source {
        sources.push(WatchedMaterialSource::new(
            "crl",
            crl_source.clone(),
            MaterialKind::Crl,
        ));
    }
    sources
}

/// Result of wiring the admin frontend TLS live-reload path. When live reload
/// is disabled (the default) every field is `None`; the caller continues
/// using the startup-loaded `Arc<rustls::ServerConfig>` directly.
pub struct AdminFrontendTlsReloadHandles {
    /// Pre-populated shared slot the admin HTTPS listener loads on each
    /// accept. `Some` only when live reload is enabled.
    pub slot: Option<SharedFrontendTls>,
    /// Handle to the spawned watcher task. `Some` only when live reload is
    /// enabled. The watcher self-terminates when the shutdown receiver it
    /// holds fires, so callers may safely detach this handle by dropping
    /// it — the task will exit on its own at gateway shutdown.
    pub watcher_handle: Option<JoinHandle<()>>,
}

/// Build the admin frontend TLS slot + reload watcher. Admin listeners do
/// NOT apply `enable_early_data` (no 425 guard on admin) and do NOT opt into
/// kTLS — the rebuild closure runs the same vanilla path as the startup
/// admin TLS load.
pub fn prepare_admin_frontend_tls(
    tls_config: Arc<ServerConfig>,
    startup_client_trust: Option<AcceptedClientTrust>,
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &CrlList,
    shutdown_rx: Option<watch::Receiver<bool>>,
) -> AdminFrontendTlsReloadHandles {
    if !env_config.frontend_tls_live_reload_enabled {
        return AdminFrontendTlsReloadHandles {
            slot: None,
            watcher_handle: None,
        };
    }

    let (Some(cert_path), Some(key_path)) = (
        env_config.admin_tls_cert_path.clone(),
        env_config.admin_tls_key_path.clone(),
    ) else {
        return AdminFrontendTlsReloadHandles {
            slot: None,
            watcher_handle: None,
        };
    };
    let cert_source = CertSource::parse(cert_path, MaterialKind::Cert);
    let key_source = CertSource::parse(key_path, MaterialKind::Key);
    let client_ca_source = env_config
        .admin_tls_client_ca_bundle_path
        .clone()
        .map(|source| CertSource::parse(source, MaterialKind::CaBundle));
    let ocsp_source = env_config
        .admin_tls_ocsp_response_source
        .clone()
        .map(|source| CertSource::parse(source, MaterialKind::Ocsp));
    let crl_source = env_config
        .tls_crl_file_path
        .clone()
        .map(|source| CertSource::parse(source, MaterialKind::Crl));
    let watched_sources = frontend_watched_sources(
        &cert_source,
        &key_source,
        client_ca_source.as_ref(),
        ocsp_source.as_ref(),
        crl_source.as_ref(),
    );
    if !watched_sources
        .iter()
        .any(|source| source_is_refreshable(&source.source))
    {
        info!(
            "FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true but admin TLS sources are static inline material; live reload disabled for admin HTTPS"
        );
        return AdminFrontendTlsReloadHandles {
            slot: None,
            watcher_handle: None,
        };
    };

    // Same arming contract as the proxy surface, on the admin trust domain
    // (`FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH` + the shared CRL source): the
    // baseline is the identity of the load that produced `tls_config`, never a
    // later re-read of the same source.
    // Same "only when client certificates are actually verified" rule as the
    // proxy surface (issue #3857): an admin HTTPS listener without
    // `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH`, or with admin no-verify, owns
    // no withdrawable client credential and must stay unarmed.
    let client_trust_scope = match startup_client_trust.as_ref() {
        Some(startup_client_trust) if startup_client_trust.verifier.is_some() => {
            Some(ClientTrustScope::AdminHttps)
        }
        Some(_) => {
            info!(
                "Admin HTTPS live reload is enabled without verified client-certificate authentication; the admin client-trust scope stays unarmed"
            );
            None
        }
        None => {
            warn!(
                "Frontend TLS live reload is enabled but the caller supplied no startup client-CA/CRL identity for the served admin TLS configuration; established-transport trust retirement is disabled for admin HTTPS"
            );
            None
        }
    };

    let slot = empty_frontend_tls_slot();
    if let Some(scope) = client_trust_scope
        && let Some(startup_client_trust) = startup_client_trust.as_ref()
        && let Some(verifier) = startup_client_trust.verifier.clone()
    {
        client_trust::publish_accepted_rustls_candidate(
            scope,
            startup_client_trust.material.clone(),
            verifier,
            || {
                slot.store(Arc::new(Some(tls_config.clone())));
            },
        );
    } else {
        slot.store(Arc::new(Some(tls_config.clone())));
    }
    let (revision_tx, _revision_rx) = watch::channel(0u64);
    let interval = material_set_poll_interval(
        &watched_sources,
        Duration::from_secs(env_config.frontend_tls_watch_interval_seconds.max(1)),
        Duration::from_secs(env_config.secret_refresh_interval_seconds.max(1)),
    );

    let rebuild = build_admin_rebuild_fn(
        env_config,
        tls_policy,
        crls,
        cert_source,
        key_source,
        client_ca_source,
        ocsp_source,
        env_config.tls_crl_file_path.clone(),
    );

    let handle = spawn_frontend_tls_reload_task(
        FrontendTlsReloadConfig {
            surface: "admin_https",
            sources: watched_sources,
            slot: slot.clone(),
            interval,
            revision_tx,
            rebuild,
            max_material_bytes: env_config.tls_max_material_size_bytes,
            client_trust_scope,
            // No asynchronous second consumer on the admin surface: the admin
            // listener reads the slot on each accept.
            accepted_slot: None,
        },
        shutdown_rx,
    );

    AdminFrontendTlsReloadHandles {
        slot: Some(slot),
        watcher_handle: Some(handle),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_admin_rebuild_fn(
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &CrlList,
    cert_source: CertSource,
    key_source: CertSource,
    client_ca_source: Option<CertSource>,
    ocsp_source: Option<CertSource>,
    crl_source_value: Option<String>,
) -> FrontendTlsRebuildFn {
    let admin_no_verify = env_config.admin_tls_no_verify;
    let warning_days = env_config.tls_cert_expiry_warning_days;
    let revocation_warning_days = env_config.tls_crl_expiry_warning_days;
    let policy = tls_policy.clone();
    let startup_crls = crls.clone();

    Box::new(move || -> Result<FrontendTlsRebuilt, anyhow::Error> {
        let active_crls = match crl_source_value.as_deref() {
            Some(source) => tls::load_crls(Some(source), revocation_warning_days)?,
            None => startup_crls.clone(),
        };
        let candidate = tls::load_frontend_tls_candidate(
            &cert_source,
            &key_source,
            client_ca_source.as_ref(),
            ocsp_source.as_ref(),
            admin_no_verify,
            &policy,
            warning_days,
            revocation_warning_days,
            &active_crls,
            Some(ClientTrustScope::AdminHttps),
        )?;
        Ok(FrontendTlsRebuilt {
            config: candidate.config,
            client_trust: Some(candidate.client_trust),
        })
    })
}

/// Watcher surface label for the DP CP-only-server-certificate operator
/// client-trust reload.
const DP_FRONTEND_CLIENT_TRUST_SURFACE: &str = "dp_proxy_frontend_client_trust";

/// Operator-owned frontend client trust for a data plane whose **only** server
/// certificate is control-plane delivered (issue #3857).
///
/// `modes::data_plane` deliberately creates an empty HTTPS listener slot when
/// `FERRUM_PROXY_HTTPS_PORT` is enabled and the operator configured no
/// `FERRUM_FRONTEND_TLS_CERT_PATH` / `_KEY_PATH`, so that
/// `grpc::dp_client` can install the CP server config into it. Client trust
/// stays operator-owned on that shape — CP frontend TLS never carries a
/// client-CA bundle — so the client-CA/CRL half must still be loaded, armed and
/// live-reloaded. Without it the `ProxyFrontend` scope was never armed, the CP
/// snapshot's live-verifier wrapper silently fell back to the verifier baked
/// into that snapshot, and an accepted CA/CRL change reached neither new
/// H1/H2/TCP handshakes, established transports, nor HTTP/3.
pub struct DpOperatorClientTrust {
    /// The accepted startup load: the verifier that will be installed and the
    /// semantic identity of exactly the bytes it was compiled from.
    pub client_trust: AcceptedClientTrust,
    sources: Vec<WatchedMaterialSource>,
    interval: Duration,
    client_ca_value: String,
    crl_source_value: Option<String>,
    startup_crls: CrlList,
    /// `FERRUM_TLS_CRL_EXPIRY_WARNING_DAYS`, carried so the watcher's rebuild
    /// closure can warn on a near-expiry CRL without holding `EnvConfig`.
    revocation_warning_days: u64,
}

/// Runtime wiring the DP operator client-trust watcher publishes into.
pub struct DpOperatorClientTrustWiring {
    /// The DP pairing that owns the exact H3 serving candidate and the
    /// `ProxyFrontend` publication transaction on this shape.
    pub pairing: Arc<crate::grpc::dp_client::DpFrontendH3Pairing>,
    /// The H1/H2 listener slot. Only written when CP owns no server
    /// certificate; CP material is never replaced by operator material.
    pub listener_slot: SharedFrontendTls,
    /// TCP+TLS stream listeners, which share the `ProxyFrontend` scope.
    pub stream_listeners: Arc<crate::proxy::stream_listener::StreamListenerManager>,
    /// The DP HTTP/3 revision channel. The reload loop bumps it after every
    /// accepted publication so `ProxyH3` adopts the newly paired candidate.
    pub revision_tx: watch::Sender<u64>,
}

/// Load and validate the operator client trust for the CP-only-certificate DP
/// shape, or report that the shape does not apply.
///
/// `Ok(None)` means there is nothing to arm: live reload is off, no client-CA
/// source is configured (so no transport on these listeners can ever hold a
/// withdrawable client credential), or every watched source is static inline
/// material that can never change. `Err` means client-certificate
/// authentication IS configured but its material is unusable — fail closed at
/// startup rather than serve CP material under an unknown trust baseline.
pub fn prepare_dp_operator_client_trust(
    env_config: &EnvConfig,
    crls: &CrlList,
) -> Result<Option<DpOperatorClientTrust>, anyhow::Error> {
    if !env_config.frontend_tls_live_reload_enabled {
        return Ok(None);
    }
    let Some(client_ca_value) = env_config.frontend_tls_client_ca_bundle_path.clone() else {
        // No client-CA source: this listener never requests a client
        // certificate, so no CRL or client-CA withdrawal has anything to
        // revoke. Arming would publish an empty baseline and export retirement
        // metrics for a protection with nothing to protect.
        info!(
            "Frontend TLS live reload is enabled on a data plane with no operator server certificate and no client-CA bundle; the proxy client-trust scope stays unarmed"
        );
        return Ok(None);
    };
    let client_ca_watch = WatchedMaterialSource::new(
        "client_ca",
        CertSource::parse(client_ca_value.clone(), MaterialKind::CaBundle),
        MaterialKind::CaBundle,
    );
    let mut sources = vec![client_ca_watch];
    let crl_source_value = env_config.tls_crl_file_path.clone();
    if let Some(crl_value) = crl_source_value.as_ref() {
        sources.push(WatchedMaterialSource::new(
            "crl",
            CertSource::parse(crl_value.clone(), MaterialKind::Crl),
            MaterialKind::Crl,
        ));
    }
    // The startup baseline uses the CRLs already loaded at startup — the very
    // list the CP snapshot loader compiles into its own verifier — rather than
    // re-reading `FERRUM_TLS_CRL_FILE_PATH` here. A second read could observe a
    // different generation than the material actually in service.
    let revocation_warning_days = env_config.tls_crl_expiry_warning_days;
    let client_trust = match load_dp_operator_client_trust(
        &client_ca_value,
        None,
        crls,
        revocation_warning_days,
    ) {
        Ok(client_trust) => client_trust,
        Err(error) => {
            anyhow::bail!(
                "frontend client-certificate trust is configured but could not be loaded: {error}"
            );
        }
    };

    // Static inline material cannot rotate, so it needs no generation or
    // watcher. Validate it first nevertheless: both `run` and `validate` must
    // reject a malformed operator CA before a later CP snapshot tries to use
    // it, even when there will never be a refresh event.
    if !sources
        .iter()
        .any(|source| source_is_refreshable(&source.source))
    {
        info!(
            "FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true but the data plane's operator client-trust sources are static inline material; live reload disabled for proxy client trust"
        );
        return Ok(None);
    }

    let interval = material_set_poll_interval(
        &sources,
        Duration::from_secs(env_config.frontend_tls_watch_interval_seconds.max(1)),
        Duration::from_secs(env_config.secret_refresh_interval_seconds.max(1)),
    );

    Ok(Some(DpOperatorClientTrust {
        client_trust,
        sources,
        interval,
        client_ca_value,
        crl_source_value,
        startup_crls: crls.clone(),
        revocation_warning_days,
    }))
}

/// Spawn the operator client-trust reload watcher for the CP-only-certificate
/// DP shape.
///
/// Every accepted candidate is published through
/// [`crate::grpc::dp_client::DpFrontendH3Pairing::publish_operator_client_trust`],
/// which holds the pairing lock across the whole `ProxyFrontend` rustls
/// transaction, so the live verifier, the paired H3 candidate and the published
/// generation always describe one accepted load. The loop bumps the H3 revision
/// only after that publication returns, and only for an accepted candidate.
pub fn spawn_dp_operator_client_trust_watcher(
    prepared: DpOperatorClientTrust,
    wiring: DpOperatorClientTrustWiring,
    max_material_bytes: usize,
    shutdown_rx: Option<watch::Receiver<bool>>,
) -> JoinHandle<()> {
    let DpOperatorClientTrust {
        client_trust: _,
        sources,
        interval,
        client_ca_value,
        crl_source_value,
        startup_crls,
        revocation_warning_days,
    } = prepared;
    let DpOperatorClientTrustWiring {
        pairing,
        listener_slot,
        stream_listeners,
        revision_tx,
    } = wiring;

    spawn_async_material_set_reload_task_with_startup_reconcile(
        AsyncMaterialSetReloadConfig {
            surface: DP_FRONTEND_CLIENT_TRUST_SURFACE,
            sources,
            interval,
            revision_tx,
            max_material_bytes,
            ready_tx: None,
            rebuild: Box::new(move || {
                let pairing = pairing.clone();
                let listener_slot = listener_slot.clone();
                let stream_listeners = stream_listeners.clone();
                let client_ca_value = client_ca_value.clone();
                let crl_source_value = crl_source_value.clone();
                let startup_crls = startup_crls.clone();
                async move {
                    let accepted = match load_dp_operator_client_trust(
                        &client_ca_value,
                        crl_source_value.as_deref(),
                        &startup_crls,
                        revocation_warning_days,
                    ) {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            // A refused candidate keeps the complete last-good
                            // verifier, material, generation, paired config and
                            // sessions. Recording it here is what makes
                            // "retained, not silently ignored" observable on
                            // the singular scope.
                            client_trust::record_rejected_candidate(
                                ClientTrustScope::ProxyFrontend,
                            );
                            return Err(error);
                        }
                    };
                    pairing
                        .publish_operator_client_trust(
                            accepted,
                            Some(&listener_slot),
                            Some(stream_listeners.as_ref()),
                        )
                        .await;
                    Ok(())
                }
                .boxed()
            }),
        },
        shutdown_rx,
    )
}

/// One coherent client-trust load: the client-CA source is read once and both
/// the verifier and the semantic identity come out of that single read.
fn load_dp_operator_client_trust(
    client_ca_value: &str,
    crl_source_value: Option<&str>,
    startup_crls: &CrlList,
    revocation_warning_days: u64,
) -> Result<AcceptedClientTrust, anyhow::Error> {
    let active_crls = match crl_source_value {
        Some(source) => tls::load_crls(Some(source), revocation_warning_days)?,
        None => startup_crls.clone(),
    };
    let candidate = tls::build_client_cert_verifier_candidate(client_ca_value, &active_crls)?;
    Ok(AcceptedClientTrust {
        verifier: Some(candidate.verifier),
        material: candidate.material,
    })
}

/// Build the H3-listener-side reload subscription from the proxy reload
/// handles, returning `None` when live reload is disabled. Hands the H3
/// listener the revision channel (so it wakes on each successful reload), the
/// accepted-candidate slot it adopts wholesale, and the shared config slot it
/// falls back to when no accepted candidate is published.
pub fn build_h3_frontend_tls_reload(
    handles: Option<&ProxyFrontendTlsReloadHandles>,
) -> Option<crate::http3::server::Http3FrontendTlsReload> {
    let handles = handles?;
    let slot = handles.slot.clone()?;
    let revision_rx = handles.revision_rx.clone()?;
    Some(crate::http3::server::Http3FrontendTlsReload {
        tls_slot: slot,
        accepted_slot: handles.accepted_slot.clone(),
        revision_rx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ServerConfig;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    fn install_default_crypto_provider() {
        let _ = crate::fips::base_crypto_provider().install_default();
    }

    fn dummy_server_config() -> Arc<ServerConfig> {
        install_default_crypto_provider();
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

    fn dummy_tls_policy() -> TlsPolicy {
        install_default_crypto_provider();
        TlsPolicy {
            protocol_versions: vec![&rustls::version::TLS13],
            crypto_provider: Arc::new(crate::fips::base_crypto_provider()),
            prefer_server_cipher_order: false,
            session_cache_size: 64,
            early_data_max_size: 0,
        }
    }

    #[test]
    fn proxy_frontend_tls_default_is_no_watch_and_no_slot() {
        let cfg = EnvConfig::default(); // live reload defaults to false
        let policy = dummy_tls_policy();
        let crls = Arc::new(Vec::new());
        let tls_config = dummy_server_config();

        let handles = prepare_proxy_frontend_tls(tls_config, None, &cfg, &policy, &crls, None);

        assert!(
            handles.slot.is_none(),
            "default-off live reload must not allocate a slot"
        );
        assert!(handles.revision_rx.is_none());
        assert!(handles.watcher_handle.is_none());
    }

    #[test]
    fn proxy_frontend_tls_opt_in_without_cert_path_stays_quiet() {
        // Live reload is requested but cert/key paths are unset. The helper
        // should defensively no-op rather than panic; the listener startup
        // path would have already skipped HTTPS in this scenario.
        let cfg = EnvConfig {
            frontend_tls_live_reload_enabled: true,
            frontend_tls_cert_path: None,
            frontend_tls_key_path: None,
            ..EnvConfig::default()
        };
        let policy = dummy_tls_policy();
        let crls = Arc::new(Vec::new());
        let tls_config = dummy_server_config();

        let handles = prepare_proxy_frontend_tls(tls_config, None, &cfg, &policy, &crls, None);

        assert!(handles.slot.is_none());
        assert!(handles.watcher_handle.is_none());
    }

    #[tokio::test]
    async fn proxy_frontend_tls_opt_in_with_paths_returns_slot_and_handle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        // The watcher only reads file fingerprints at this stage — the
        // closure is only invoked on a detected change, so placeholder
        // bytes are fine for this test.
        std::fs::write(&cert_path, b"placeholder cert").expect("write cert");
        std::fs::write(&key_path, b"placeholder key").expect("write key");

        let cfg = EnvConfig {
            frontend_tls_live_reload_enabled: true,
            frontend_tls_cert_path: Some(cert_path.to_string_lossy().into_owned()),
            frontend_tls_key_path: Some(key_path.to_string_lossy().into_owned()),
            frontend_tls_watch_interval_seconds: 60,
            ..EnvConfig::default()
        };

        let policy = dummy_tls_policy();
        let crls = Arc::new(Vec::new());
        let tls_config = dummy_server_config();

        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let handles =
            prepare_proxy_frontend_tls(tls_config, None, &cfg, &policy, &crls, Some(shutdown_rx));

        let slot = handles.slot.expect("slot present when live reload opt-in");
        assert!(slot.load().is_some(), "slot should be pre-populated");
        assert!(
            handles.revision_rx.is_some(),
            "live reload should expose a revision channel for the H3 listener"
        );
        let handle = handles
            .watcher_handle
            .expect("live reload should spawn a watcher task");
        handle.abort();
    }

    #[test]
    fn frontend_watched_sources_include_optional_client_ca_and_crl() {
        let cert = CertSource::parse("/tmp/cert.pem", MaterialKind::Cert);
        let key = CertSource::parse("/tmp/key.pem", MaterialKind::Key);
        let client_ca = CertSource::parse("/tmp/client-ca.pem", MaterialKind::CaBundle);
        let ocsp = CertSource::parse("/tmp/ocsp.der", MaterialKind::Ocsp);
        let crl = CertSource::parse("/tmp/revocations.pem", MaterialKind::Crl);

        let watched =
            frontend_watched_sources(&cert, &key, Some(&client_ca), Some(&ocsp), Some(&crl));
        let labels = watched
            .iter()
            .map(|source| source.label)
            .collect::<Vec<_>>();

        assert_eq!(labels, vec!["cert", "key", "client_ca", "ocsp", "crl"]);
    }

    #[test]
    fn admin_frontend_tls_default_is_no_watch_and_no_slot() {
        let cfg = EnvConfig::default();
        let policy = dummy_tls_policy();
        let crls = Arc::new(Vec::new());
        let tls_config = dummy_server_config();

        let handles = prepare_admin_frontend_tls(tls_config, None, &cfg, &policy, &crls, None);

        assert!(handles.slot.is_none());
        assert!(handles.watcher_handle.is_none());
    }
}
