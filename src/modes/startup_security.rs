//! Side-effect-free startup security loaders shared by `ferrum-edge validate`
//! and serving-mode `run`/`serve` paths.
//!
//! These surfaces historically lived only inside mode `serve()` bodies, so
//! `validate` could report success for configs that refuse to start. Keeping
//! the loaders in one place prevents that drift: both commands exercise the
//! same TLS policy, CRL, admin CIDR, metrics-auth, frontend/admin TLS, and
//! DTLS material checks for each mode's applicable scope.
//!
//! Loaders here must not bind sockets, spawn servers, mutate durable stores,
//! mint random secrets, or resolve unrelated external state beyond what
//! startup necessarily validates (local/materialized TLS sources and env).

use std::sync::Arc;

use anyhow::Context as _;

use crate::admin::MetricsAuthPolicy;
use crate::config::conf_file::resolve_ferrum_var;
use crate::config::env_config::{EnvConfig, OperatingMode};
use crate::modes::mesh::MeshTopology;
use crate::proxy::client_ip::TrustedProxies;
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
use crate::tls::{self, CrlList, TlsPolicy};

/// Which env-level security surfaces a mode hard-fails on at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupSecurityScope {
    /// `TlsPolicy::from_env_config` + `tls::load_crls`.
    pub tls_policy_and_crls: bool,
    /// Strict `FERRUM_ADMIN_ALLOWED_CIDRS` + `MetricsAuthPolicy::from_env`.
    pub admin_cidrs_and_metrics: bool,
    /// Frontend cert/key pair via `load_tls_config_with_client_auth_and_ocsp`
    /// when both paths are set (proxy-serving modes).
    pub frontend_tls: bool,
    /// Admin HTTPS cert/key pair when `admin_https_listener_enabled()`.
    pub admin_tls: bool,
    /// DTLS frontend cert (+ optional client CA) expiry when both DTLS paths
    /// are set.
    pub dtls: bool,
}

impl StartupSecurityScope {
    /// Mode-specific surfaces that `run` hard-fails on before accepting
    /// traffic. Injector/migrate keep their own specialized loaders and are
    /// out of scope here. Admin JWT is intentionally excluded: file/mesh/
    /// node_agent mint a random secret on unset (a serve-time side effect),
    /// while database/cp/dp require a secret — validate covers the TLS/CIDR/
    /// metrics loaders listed in issue #2976 without changing JWT semantics.
    pub fn for_mode(mode: &OperatingMode) -> Self {
        match mode {
            OperatingMode::File | OperatingMode::Database | OperatingMode::DataPlane => Self {
                tls_policy_and_crls: true,
                admin_cidrs_and_metrics: true,
                frontend_tls: true,
                admin_tls: true,
                dtls: true,
            },
            OperatingMode::ControlPlane => Self {
                tls_policy_and_crls: true,
                admin_cidrs_and_metrics: true,
                frontend_tls: false,
                admin_tls: true,
                dtls: false,
            },
            OperatingMode::Mesh => Self {
                tls_policy_and_crls: true,
                admin_cidrs_and_metrics: true,
                // Mesh frontend identity is specialized (SVID fallback /
                // `load_mesh_server_identity`). When an explicit frontend
                // cert/key pair is set, validate that pair the same way mesh
                // startup does; also validate a configured inbound client CA
                // against the no-slice PERMISSIVE baseline when a terminating
                // listener would snapshot it (see
                // `validate_mesh_inbound_client_ca_from_env`).
                // DTLS is not a mesh startup gate here.
                frontend_tls: true,
                admin_tls: true,
                dtls: false,
            },
            OperatingMode::NodeAgent => Self {
                // TLS policy/CRLs + admin TLS material are in scope for node-agent
                // so validate/run share one surface, but
                // `load_startup_security_with_scope` only loads them when the
                // admin surface is active or HTTPS was explicitly requested
                // (issue #3704). HTTP-only / admin-disabled installs do not fail
                // on unrelated TLS policy or CRL settings.
                tls_policy_and_crls: true,
                // Parsed only when the node-agent admin listener would start.
                admin_cidrs_and_metrics: true,
                frontend_tls: false,
                admin_tls: true,
                dtls: false,
            },
            OperatingMode::Injector | OperatingMode::Migrate => Self {
                tls_policy_and_crls: false,
                admin_cidrs_and_metrics: false,
                frontend_tls: false,
                admin_tls: false,
                dtls: false,
            },
        }
    }

    pub fn is_empty(self) -> bool {
        !self.tls_policy_and_crls
            && !self.admin_cidrs_and_metrics
            && !self.frontend_tls
            && !self.admin_tls
            && !self.dtls
    }
}

/// Materials produced by the shared env-security loaders.
///
/// Serving modes reuse these so validate and run cannot diverge on the same
/// inputs. Optional fields are `None` when the active scope skips that surface
/// or when the corresponding env pair is unset.
pub struct StartupSecurityMaterials {
    pub tls_policy: Option<TlsPolicy>,
    pub crls: CrlList,
    pub admin_allowed_cidrs: Option<TrustedProxies>,
    pub metrics_auth: Option<MetricsAuthPolicy>,
    pub frontend_tls: Option<Arc<rustls::ServerConfig>>,
    pub admin_tls: Option<Arc<rustls::ServerConfig>>,
}

impl StartupSecurityMaterials {
    fn empty() -> Self {
        Self {
            tls_policy: None,
            crls: Arc::new(Vec::new()),
            admin_allowed_cidrs: None,
            metrics_auth: None,
            frontend_tls: None,
            admin_tls: None,
        }
    }
}

/// Load every in-scope env security surface for `env_config.mode`.
///
/// Side-effect free: does not bind, spawn, mutate stores, or mint secrets.
pub fn load_startup_security(
    env_config: &EnvConfig,
) -> Result<StartupSecurityMaterials, anyhow::Error> {
    let scope = StartupSecurityScope::for_mode(&env_config.mode);
    load_startup_security_with_scope(env_config, scope)
}

/// Load env security surfaces for an explicit scope (tests / specialized
/// callers). Mesh frontend uses `load_mesh_server_identity` when both
/// frontend paths are set; other proxy modes use the standard frontend
/// TLS loader.
pub fn load_startup_security_with_scope(
    env_config: &EnvConfig,
    scope: StartupSecurityScope,
) -> Result<StartupSecurityMaterials, anyhow::Error> {
    if scope.is_empty() {
        return Ok(StartupSecurityMaterials::empty());
    }

    // Node-agent only parses CIDRs/metrics when `node_agent_admin_surface_active`
    // is true — plaintext HTTP and/or complete HTTPS that would bind. HTTP=0
    // plus explicit incomplete HTTPS is *not* an active admin surface here, so
    // CIDR/metrics are skipped in that shape; fail-closed validation for that
    // incomplete HTTPS intent comes from the HTTPS-security / admin-TLS branch
    // below (`node_agent_admin_https_security_applicable`).
    let node_agent_admin_active =
        env_config.mode != OperatingMode::NodeAgent || node_agent_admin_surface_active(env_config);
    // Newly node-agent-owned TLS policy / CRL / admin TLS loads are gated on an
    // active or explicitly requested admin HTTPS surface so a disabled or
    // HTTP-only node-agent does not fail on unrelated TLS policy or CRL env.
    let node_agent_https_security = env_config.mode != OperatingMode::NodeAgent
        || node_agent_admin_https_security_applicable(env_config);

    let mut materials = StartupSecurityMaterials::empty();

    if scope.tls_policy_and_crls && node_agent_https_security {
        materials.tls_policy = Some(load_tls_policy(env_config)?);
        materials.crls = load_crls_from_env(env_config)?;
    }

    if scope.admin_cidrs_and_metrics && node_agent_admin_active {
        materials.admin_allowed_cidrs = Some(load_admin_allowed_cidrs(env_config)?);
        materials.metrics_auth = Some(load_metrics_auth(env_config)?);
    }

    let tls_policy_ref = materials.tls_policy.as_ref();
    if scope.frontend_tls {
        materials.frontend_tls = match env_config.mode {
            OperatingMode::Mesh => {
                let frontend_tls = load_mesh_explicit_frontend_tls(env_config)?;
                // Mesh run snapshots `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH`
                // via `mesh_inbound_tls_reload_snapshot_for_listener` on the
                // no-slice PERMISSIVE baseline when a terminating inbound
                // listener would consume it. Validate that material here so
                // missing/unreadable CA bytes cannot drift; PEM/expiry checks
                // apply only when a mesh server identity would also be built.
                validate_mesh_inbound_client_ca_from_env(env_config)?;
                frontend_tls
            }
            _ => {
                let policy = tls_policy_ref.ok_or_else(|| {
                    anyhow::anyhow!(
                        "internal error: frontend TLS validation requires TLS policy scope"
                    )
                })?;
                try_load_frontend_tls(env_config, policy, &materials.crls)?
            }
        };
    }

    if scope.admin_tls {
        if env_config.mode == OperatingMode::NodeAgent {
            if node_agent_https_security {
                let policy = tls_policy_ref.ok_or_else(|| {
                    anyhow::anyhow!(
                        "internal error: admin TLS validation requires TLS policy scope"
                    )
                })?;
                materials.admin_tls = load_admin_https_tls_fail_closed(
                    env_config,
                    policy,
                    &materials.crls,
                    "Invalid node_agent admin TLS configuration",
                )?;
            }
        } else {
            let policy = tls_policy_ref.ok_or_else(|| {
                anyhow::anyhow!("internal error: admin TLS validation requires TLS policy scope")
            })?;
            let label = if env_config.mode == OperatingMode::Mesh {
                "Invalid mesh admin TLS configuration"
            } else {
                "Invalid admin TLS configuration"
            };
            materials.admin_tls = try_load_admin_tls(env_config, policy, &materials.crls, label)?;
        }
    }

    if scope.dtls {
        validate_dtls_material(env_config)?;
    }

    Ok(materials)
}

/// `TlsPolicy::from_env_config` — shared by validate and serve.
pub fn load_tls_policy(env_config: &EnvConfig) -> Result<TlsPolicy, anyhow::Error> {
    TlsPolicy::from_env_config(env_config)
}

/// `tls::load_crls` for `FERRUM_TLS_CRL_FILE_PATH` — shared by validate and serve.
pub fn load_crls_from_env(env_config: &EnvConfig) -> Result<CrlList, anyhow::Error> {
    tls::load_crls(env_config.tls_crl_file_path.as_deref())
}

/// Strict `FERRUM_ADMIN_ALLOWED_CIDRS` parse — shared by validate and serve.
pub fn load_admin_allowed_cidrs(env_config: &EnvConfig) -> Result<TrustedProxies, anyhow::Error> {
    TrustedProxies::parse_strict(
        &env_config.admin_allowed_cidrs,
        "FERRUM_ADMIN_ALLOWED_CIDRS",
    )
    .map_err(|e| anyhow::anyhow!("FERRUM_ADMIN_ALLOWED_CIDRS: {}", e))
}

/// `MetricsAuthPolicy::from_env` — shared by validate and serve.
pub fn load_metrics_auth(env_config: &EnvConfig) -> Result<MetricsAuthPolicy, anyhow::Error> {
    MetricsAuthPolicy::from_env(env_config).map_err(|e| anyhow::anyhow!(e))
}

/// Load frontend TLS when both cert and key paths are set.
///
/// Returns `Ok(None)` when either path is unset (HTTP-only / deferred). On
/// failure, preserves the serving-mode error context
/// (`Invalid TLS configuration: …`). Does not apply early-data or kTLS
/// opt-ins — callers that serve traffic apply those after a successful load.
pub fn try_load_frontend_tls(
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &CrlList,
) -> Result<Option<Arc<rustls::ServerConfig>>, anyhow::Error> {
    let (Some(cert_path), Some(key_path)) = (
        &env_config.frontend_tls_cert_path,
        &env_config.frontend_tls_key_path,
    ) else {
        return Ok(None);
    };

    tls::load_tls_config_with_client_auth_and_ocsp(
        cert_path,
        key_path,
        env_config.frontend_tls_client_ca_bundle_path.as_deref(),
        env_config.frontend_tls_ocsp_response_source.as_deref(),
        false,
        tls_policy,
        env_config.tls_cert_expiry_warning_days,
        crls,
    )
    .map(Some)
    .map_err(|e| anyhow::anyhow!("Invalid TLS configuration: {}", e))
}

/// Load admin TLS when the HTTPS listener would be enabled
/// (`admin_https_listener_enabled`: port ≠ 0 and both cert/key paths set).
///
/// `error_label` preserves mode-specific wording (`Invalid admin TLS
/// configuration` vs `Invalid mesh admin TLS configuration`).
pub fn try_load_admin_tls(
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &CrlList,
    error_label: &str,
) -> Result<Option<Arc<rustls::ServerConfig>>, anyhow::Error> {
    if !env_config.admin_https_listener_enabled() {
        return Ok(None);
    }
    load_admin_tls_material(env_config, tls_policy, crls, error_label).map(Some)
}

/// Load admin TLS material whenever both cert and key paths are set.
///
/// Used by serving modes that may also adopt a pre-bound admin HTTPS socket
/// when `FERRUM_ADMIN_HTTPS_PORT=0`. `validate` uses [`try_load_admin_tls`],
/// which additionally requires a nonzero HTTPS port.
pub fn load_admin_tls_material(
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &CrlList,
    error_label: &str,
) -> Result<Arc<rustls::ServerConfig>, anyhow::Error> {
    let (Some(admin_cert), Some(admin_key)) = (
        &env_config.admin_tls_cert_path,
        &env_config.admin_tls_key_path,
    ) else {
        return Err(anyhow::anyhow!(
            "{error_label}: admin TLS cert and key paths must both be set"
        ));
    };

    tls::load_tls_config_with_client_auth_and_ocsp(
        admin_cert,
        admin_key,
        env_config.admin_tls_client_ca_bundle_path.as_deref(),
        env_config.admin_tls_ocsp_response_source.as_deref(),
        env_config.admin_tls_no_verify,
        tls_policy,
        env_config.tls_cert_expiry_warning_days,
        crls,
    )
    .map_err(|e| anyhow::anyhow!("{}: {}", error_label, e))
}

/// Whether node-agent mode should start any admin listener surface.
///
/// True when admin is opted in and at least one of plaintext HTTP or
/// configured HTTPS would bind. HTTPS follows the shared
/// [`EnvConfig::admin_https_listener_enabled`] contract (nonzero port + both
/// cert/key paths).
pub fn node_agent_admin_surface_active(env_config: &EnvConfig) -> bool {
    env_config.node_agent_admin_enabled
        && (env_config.admin_http_port != 0 || env_config.admin_https_listener_enabled())
}

/// Whether node-agent should load TLS policy / CRL / admin TLS at validate/run.
///
/// True when admin is enabled and HTTPS is either fully configured to bind or
/// explicitly requested with a nonzero port (including incomplete material that
/// must fail closed). Inherited default `9443` without TLS is not applicable.
pub fn node_agent_admin_https_security_applicable(env_config: &EnvConfig) -> bool {
    if !env_config.node_agent_admin_enabled || env_config.admin_https_port == 0 {
        return false;
    }
    env_config.admin_https_listener_enabled() || env_config.admin_https_explicitly_requested()
}

/// Fully prepared admin HTTPS listener materials shared by serving modes.
///
/// TLS material is validated before any plaintext admin task is spawned so a
/// bad cert/key cannot orphan an already-running HTTP listener.
pub struct PlannedAdminHttps {
    pub addr: std::net::SocketAddr,
    pub tls_config: Arc<rustls::ServerConfig>,
    pub reload: crate::modes::tls_reload::AdminFrontendTlsReloadHandles,
}

/// Independent admin HTTPS listener plan used by node-agent and other serving
/// modes. HTTP and HTTPS ports are decided separately; HTTPS is never gated on
/// a nonzero HTTP port.
pub enum AdminHttpsListenerPlan {
    /// `FERRUM_ADMIN_HTTPS_PORT=0` — disable sentinel.
    DisabledByPort,
    /// Inherited nonzero default HTTPS port without an explicit operator
    /// request and without TLS material — keep HTTP-only compatibility.
    DisabledByMissingTls,
    /// HTTPS listener should bind with the prepared TLS runtime.
    Enabled(PlannedAdminHttps),
}

/// Load admin HTTPS TLS when enabled, or fail closed on explicit incomplete
/// configuration (issue #3704).
///
/// - Port `0` → `Ok(None)`
/// - Inherited default port without TLS / without explicit request → `Ok(None)`
/// - Partial cert/key → error
/// - Explicit nonzero port without both paths → error
/// - Both paths set → load material (fail closed on invalid/unreadable/mismatched)
pub fn load_admin_https_tls_fail_closed(
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &CrlList,
    error_label: &str,
) -> Result<Option<Arc<rustls::ServerConfig>>, anyhow::Error> {
    if env_config.admin_https_port == 0 {
        return Ok(None);
    }
    match (
        env_config.admin_tls_cert_path.as_ref(),
        env_config.admin_tls_key_path.as_ref(),
    ) {
        (None, None) => {
            if env_config.admin_https_explicitly_requested() {
                return Err(anyhow::anyhow!(
                    "{error_label}: FERRUM_ADMIN_HTTPS_PORT is explicitly configured but \
                     FERRUM_ADMIN_TLS_CERT_PATH and FERRUM_ADMIN_TLS_KEY_PATH are missing — \
                     set both TLS paths or set FERRUM_ADMIN_HTTPS_PORT=0"
                ));
            }
            Ok(None)
        }
        (Some(_), None) => Err(anyhow::anyhow!(
            "{error_label}: FERRUM_ADMIN_TLS_CERT_PATH is set but FERRUM_ADMIN_TLS_KEY_PATH is \
             missing — both must be configured together"
        )),
        (None, Some(_)) => Err(anyhow::anyhow!(
            "{error_label}: FERRUM_ADMIN_TLS_KEY_PATH is set but FERRUM_ADMIN_TLS_CERT_PATH is \
             missing — both must be configured together"
        )),
        (Some(_), Some(_)) => {
            load_admin_tls_material(env_config, tls_policy, crls, error_label).map(Some)
        }
    }
}

/// Plan the binary-owned admin HTTPS listener from `EnvConfig`.
///
/// - Port `0` → [`AdminHttpsListenerPlan::DisabledByPort`]
/// - Inherited default nonzero port without explicit request and without TLS →
///   [`AdminHttpsListenerPlan::DisabledByMissingTls`] (HTTP-only compatible)
/// - Explicit nonzero port or partial/complete TLS material → load TLS and fail
///   closed on missing/partial/unreadable/mismatched/malformed material
///
/// Callers must invoke this **before** spawning a plaintext admin listener so
/// startup rollback owns every handle (issue #2372 / #3704).
pub fn plan_admin_https_listener(
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &CrlList,
    error_label: &str,
    addr: std::net::SocketAddr,
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<AdminHttpsListenerPlan, anyhow::Error> {
    if env_config.admin_https_port == 0 {
        return Ok(AdminHttpsListenerPlan::DisabledByPort);
    }

    let Some(tls_config) =
        load_admin_https_tls_fail_closed(env_config, tls_policy, crls, error_label)?
    else {
        return Ok(AdminHttpsListenerPlan::DisabledByMissingTls);
    };

    let reload = crate::modes::tls_reload::prepare_admin_frontend_tls(
        tls_config.clone(),
        env_config,
        tls_policy,
        crls,
        shutdown_rx,
    );
    Ok(AdminHttpsListenerPlan::Enabled(PlannedAdminHttps {
        addr,
        tls_config,
        reload,
    }))
}

/// Validate DTLS frontend cert (+ optional client CA) expiry when both DTLS
/// cert and key paths are set. Matches file/database/dp `serve()` gates.
pub fn validate_dtls_material(env_config: &EnvConfig) -> Result<(), anyhow::Error> {
    let (Some(cert_path), Some(_key_path)) =
        (&env_config.dtls_cert_path, &env_config.dtls_key_path)
    else {
        return Ok(());
    };

    tls::check_cert_expiry(
        cert_path,
        "DTLS frontend cert",
        env_config.tls_cert_expiry_warning_days,
    )
    .map_err(|e| e.context("Invalid DTLS frontend cert"))?;

    if let Some(ref ca_path) = env_config.dtls_client_ca_cert_path {
        tls::check_cert_expiry(
            ca_path,
            "DTLS client CA cert",
            env_config.tls_cert_expiry_warning_days,
        )
        .map_err(|e| e.context("Invalid DTLS client CA cert"))?;
    }

    Ok(())
}

/// Mesh-only: when an explicit frontend cert/key pair is set, validate it the
/// same way mesh startup does (`load_mesh_server_identity`). SVID / CA-backend
/// fallbacks stay on the mesh serve path (they need runtime slots).
fn load_mesh_explicit_frontend_tls(
    env_config: &EnvConfig,
) -> Result<Option<Arc<rustls::ServerConfig>>, anyhow::Error> {
    let (Some(cert_path), Some(key_path)) = (
        env_config.frontend_tls_cert_path.as_deref(),
        env_config.frontend_tls_key_path.as_deref(),
    ) else {
        return Ok(None);
    };

    // `load_mesh_server_identity` validates expiry + key match. We do not need
    // the resulting identity for validate; discard it after a successful load.
    // Returning `None` for `frontend_tls` materials keeps the field meaning
    // "standard Arc<ServerConfig>" while still failing closed on bad material.
    let _identity = tls::load_mesh_server_identity(
        cert_path,
        key_path,
        env_config.tls_cert_expiry_warning_days,
    )?;
    Ok(None)
}

/// Whether mesh inbound TLS snapshot construction would read a configured
/// client CA. Mirrors `mesh_inbound_tls_reload_snapshot`: true when the
/// workload-level mode or any per-port override is not DISABLE.
#[inline]
pub fn mesh_inbound_modes_need_client_ca(
    default_mode_enables_mtls: bool,
    any_port_enables_mtls: bool,
) -> bool {
    default_mode_enables_mtls || any_port_enables_mtls
}

/// Load mesh inbound client-CA bundle bytes.
///
/// Shared by mesh `run`'s `mesh_inbound_tls_reload_snapshot` and `validate` so
/// missing/unreadable configured CA material cannot drift between the two.
pub fn load_mesh_inbound_client_ca_bundle(
    path: &str,
) -> Result<(String, Arc<[u8]>), anyhow::Error> {
    let source = CertSource::parse(path, MaterialKind::CaBundle);
    let material = load_material_blocking(&source, MaterialKind::CaBundle).with_context(|| {
        format!(
            "failed to load mesh frontend client CA bundle at {}",
            source.redacted_source_id()
        )
    })?;
    let pem: Arc<[u8]> = material.bytes.expose_secret().to_vec().into();
    Ok((material.display_source_id, pem))
}

/// Whether mesh `run` would resolve a configured inbound server identity.
///
/// Mirrors the source selection in `load_mesh_frontend_server_identity`:
/// explicit frontend cert/key, gateway SVID file cert/key, then a non-`None`
/// `CaBackend` from `FERRUM_MESH_CA_BACKEND`. This is a configuration presence
/// check (not a material load): validate cannot fetch runtime SVID slots, but
/// it must still know whether `load_mesh_frontend_tls` would leave
/// `server_identity` as `None` under PERMISSIVE (plaintext) or proceed into
/// `load_mesh_tls_config_with_identity_and_client_ca_bytes`.
pub fn mesh_inbound_server_identity_configured(
    env_config: &EnvConfig,
) -> Result<bool, anyhow::Error> {
    if env_config.frontend_tls_cert_path.is_some() && env_config.frontend_tls_key_path.is_some() {
        return Ok(true);
    }
    if env_config.gateway_svid_cert_path.is_some() && env_config.gateway_svid_key_path.is_some() {
        return Ok(true);
    }
    let ca_backend = crate::identity::ca::CaBackend::from_str_lossy(&env_config.mesh_ca_backend)
        .map_err(|error| anyhow::anyhow!("Invalid FERRUM_MESH_CA_BACKEND: {error}"))?;
    Ok(ca_backend != crate::identity::ca::CaBackend::None)
}

/// Validate a configured mesh inbound client CA when run would consume it.
///
/// Applicability mirrors `mesh_inbound_tls_reload_snapshot_for_listener`:
/// passthrough-only topologies (`has_inbound_tls_termination_listener == false`)
/// and fully DISABLE mTLS modes skip the CA even when the path is set.
///
/// When applicable and the path is set, always loads bytes the same way run's
/// snapshot does (missing/unreadable material fails closed). PEM/expiry
/// parsing runs only when a mesh server identity is also configured: under
/// PERMISSIVE with no identity, `load_mesh_frontend_tls` returns `Ok(None)`
/// before calling `load_mesh_tls_config_with_identity_and_client_ca_bytes`, so
/// validate must not PEM-reject that plaintext path.
pub fn validate_mesh_inbound_client_ca_if_applicable(
    env_config: &EnvConfig,
    has_inbound_tls_termination_listener: bool,
    mtls_needs_client_ca: bool,
) -> Result<(), anyhow::Error> {
    if !has_inbound_tls_termination_listener || !mtls_needs_client_ca {
        return Ok(());
    }
    let Some(path) = env_config.frontend_tls_client_ca_bundle_path.as_deref() else {
        return Ok(());
    };

    let (display_path, pem) = load_mesh_inbound_client_ca_bundle(path)?;
    if !mesh_inbound_server_identity_configured(env_config)? {
        return Ok(());
    }
    tls::check_cert_expiry_from_pem_bytes(
        pem.as_ref(),
        "mesh client CA bundle",
        &display_path,
        env_config.tls_cert_expiry_warning_days,
    )?;
    Ok(())
}

/// Mesh validate/run startup gate for `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH`.
///
/// Resolves topology from the process env the same way mesh run does (default
/// `sidecar`). `validate` cannot fetch an applied PeerAuthentication slice, so
/// it uses the no-slice PERMISSIVE baseline with an empty per-port table
/// (`resolve_inbound_mtls_mode(None)`): a configured client CA is loaded on
/// terminating topologies. A later all-DISABLE dynamic slice may leave that CA
/// unused at runtime; validate may therefore conservatively reject a
/// configured CA that such a slice would not consume. It does **not** claim
/// exact knowledge of the effective live mTLS mode.
fn validate_mesh_inbound_client_ca_from_env(env_config: &EnvConfig) -> Result<(), anyhow::Error> {
    let topology_raw =
        resolve_ferrum_var("FERRUM_MESH_TOPOLOGY").unwrap_or_else(|| "sidecar".to_string());
    let topology = MeshTopology::parse(&topology_raw).map_err(anyhow::Error::msg)?;
    // No-slice startup baseline: Permissive + empty port modes ⇒ snapshot would
    // load a configured client CA on terminating topologies.
    validate_mesh_inbound_client_ca_if_applicable(
        env_config,
        topology.has_inbound_tls_termination_listener(),
        mesh_inbound_modes_need_client_ca(true, false),
    )
}
