//! Database-independent admission of a `POST /restore` payload (issue #7532).
//!
//! `POST /restore` and `ferrum-edge validate --backup` both run
//! [`admit_restore_payload`], so the offline check accepts exactly the payloads
//! restore's payload validation accepts, for every section: the four resource
//! collections, `gateway_trust_bundles`, `api_specs` (including the strict
//! extension admission of each stored spec document) and `namespace_registry`.
//!
//! What stays in the handler is what depends on the target database, not on
//! the payload: another namespace already owning the process-global
//! `prometheus_metrics` instance, the `confirm_api_spec_deletion` confirmation
//! a backup *without* an `api_specs` section needs when the target namespace
//! holds specs, and a conditional restore's `If-Match` precondition.

use crate::admin::backup::{
    NamespaceRegistryBackupSection, RestorePayload, restore_missing_resource_id_errors,
    validate_restore_api_specs_section_with_total_limit,
};
use crate::config::BackendEgressPolicy;
use crate::config::types::{ApiSpec, GatewayConfig};

/// Top-level `error` text of every restore payload-validation refusal.
pub(crate) const RESTORE_VALIDATION_FAILED_MESSAGE: &str =
    "Restore payload validation failed — existing config was NOT deleted";

/// The node policy restore admission depends on.
#[derive(Clone)]
pub(crate) struct RestoreAdmissionPolicy {
    pub(crate) cert_expiry_days: u64,
    pub(crate) backend_allow_ips: BackendEgressPolicy,
    /// The plugin validation client, or why it could not be built.
    pub(crate) plugin_http_client: Result<crate::plugins::PluginHttpClient, String>,
    /// The cached mesh model a control plane validates mesh references
    /// against; `None` on database mode and in the offline check.
    pub(crate) mesh: Option<Box<crate::modes::mesh::config::MeshConfig>>,
    /// `FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB`.
    pub(crate) max_spec_body_mib: usize,
    /// `FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB`, in bytes.
    pub(crate) max_total_spec_bytes: usize,
}

impl RestoreAdmissionPolicy {
    /// The policy the serving restore handler applies.
    pub(crate) fn from_admin_state(state: &super::AdminState) -> Self {
        Self {
            cert_expiry_days: state
                .proxy_state
                .as_ref()
                .map(|ps| ps.env_config.tls_cert_expiry_warning_days)
                .unwrap_or(crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS),
            backend_allow_ips: state.backend_allow_ips.clone(),
            plugin_http_client: super::plugin_validation_http_client(state),
            mesh: state
                .cached_gateway_config()
                .and_then(|config| config.mesh.clone()),
            max_spec_body_mib: state.admin_spec_max_body_size_mib,
            max_total_spec_bytes: restore_max_body_bytes(state.admin_restore_max_body_size_mib),
        }
    }

    /// The policy the same environment gives a database-mode (`serves_proxy`)
    /// or control-plane admin API, for the offline `validate --backup` check.
    ///
    /// The plugin validation client carries the same backend egress policy,
    /// real-IP header and compression admission policy a serving node's plugin
    /// cache admits under; it makes no connection while validating.
    pub(crate) fn from_env_config(
        env_config: &crate::config::EnvConfig,
        serves_proxy: bool,
    ) -> Self {
        let plugin_http_client = crate::config::CompressionAdmissionPolicy::from_process_env().map(
            |compression_policy| {
                crate::plugins::PluginHttpClient::default_with_backend_allow_ips(
                    env_config.backend_allow_ips.clone(),
                )
                .with_real_ip_header(crate::config::env_config::resolve_real_ip_header())
                .with_compression_admission_policy(compression_policy)
            },
        );
        Self {
            cert_expiry_days: if serves_proxy {
                env_config.tls_cert_expiry_warning_days
            } else {
                crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS
            },
            backend_allow_ips: env_config.backend_allow_ips.clone(),
            plugin_http_client,
            mesh: None,
            max_spec_body_mib: env_config.admin_spec_max_body_size_mib,
            max_total_spec_bytes: restore_max_body_bytes(
                env_config.admin_restore_max_body_size_mib,
            ),
        }
    }
}

/// `FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB` in bytes, the request-body ceiling
/// `POST /restore` reads under and the size the offline check reads under.
pub(crate) fn restore_max_body_bytes(mib: usize) -> usize {
    mib.saturating_mul(1024 * 1024)
}

/// A payload restore admitted, ready for the database-dependent checks and
/// persistence.
pub(crate) struct AdmittedRestore {
    /// Canonical resources stamped with the target namespace; trust records
    /// stamped, normalized and validated. `api_specs` and
    /// `namespace_registry` are moved out into the fields below.
    pub(crate) payload: RestorePayload,
    /// `Some` when the payload carried the versioned `api_specs` section.
    pub(crate) api_specs: Option<Vec<ApiSpec>>,
    /// `Some(description)` when the payload carried a `namespace_registry`
    /// section taken from the target namespace itself; that is the row restore
    /// writes after the configuration commits. A section taken from another
    /// namespace is admitted but never applied: restoring tenant A's export
    /// into tenant B must not relabel B with A's registry metadata.
    pub(crate) namespace_registry_description: Option<Option<String>>,
    /// Whether the payload carried a `namespace_registry` section at all.
    pub(crate) namespace_registry_present: bool,
}

impl AdmittedRestore {
    /// Resource and section counts, for the offline check's report.
    pub(crate) fn summary(&self) -> RestoreSummary {
        RestoreSummary {
            proxies: self.payload.proxies.len(),
            consumers: self.payload.consumers.len(),
            plugin_configs: self.payload.plugin_configs.len(),
            upstreams: self.payload.upstreams.len(),
            api_specs: self.api_specs.as_ref().map(Vec::len),
            gateway_trust_bundles: self.payload.gateway_trust_bundles.as_ref().map(Vec::len),
            namespace_registry: match (
                self.namespace_registry_present,
                self.namespace_registry_description.is_some(),
            ) {
                (false, _) => NamespaceRegistryOutcome::Absent,
                (true, true) => NamespaceRegistryOutcome::Applied,
                (true, false) => NamespaceRegistryOutcome::OtherNamespace,
            },
        }
    }
}

/// What an admitted payload would restore. `None` marks an absent section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RestoreSummary {
    pub(crate) proxies: usize,
    pub(crate) consumers: usize,
    pub(crate) plugin_configs: usize,
    pub(crate) upstreams: usize,
    pub(crate) api_specs: Option<usize>,
    pub(crate) gateway_trust_bundles: Option<usize>,
    pub(crate) namespace_registry: NamespaceRegistryOutcome,
}

/// What restore does with a payload's `namespace_registry` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NamespaceRegistryOutcome {
    /// No section: the target's registry row is left untouched.
    Absent,
    /// The section names the target namespace: its row is written.
    Applied,
    /// The section names another namespace: admitted, not applied.
    OtherNamespace,
}

/// Why restore admission refused a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RestoreAdmissionError {
    /// `400 {"error": ...}`: the body is not a restore envelope, or names an
    /// incompatible version.
    Invalid(String),
    /// `400 {"error": RESTORE_VALIDATION_FAILED_MESSAGE, "validation_errors": [...]}`.
    Validation(Vec<String>),
    /// `503`: validation could not run (the plugin validation client could
    /// not be built). Nothing about the payload was decided.
    Unavailable(String),
}

impl RestoreAdmissionError {
    /// The refusal as an operator-facing list (the offline check's output).
    pub(crate) fn messages(&self) -> Vec<String> {
        match self {
            Self::Invalid(message) | Self::Unavailable(message) => vec![message.clone()],
            Self::Validation(errors) => errors.clone(),
        }
    }
}

/// Parse a `POST /restore` body exactly as the handler does: the JSON-object
/// guard plus the closed `RestorePayload` envelope (issue #5538).
pub(crate) fn parse_restore_payload(body: &[u8]) -> Result<RestorePayload, RestoreAdmissionError> {
    crate::util::json_object::from_json_object_slice::<RestorePayload>(body)
        .map_err(|error| RestoreAdmissionError::Invalid(format!("Invalid JSON body: {error}")))
}

/// Every database-independent restore admission step, in the order the
/// handler reports them. CPU-bound: the handler runs it on the blocking pool.
///
/// `trust_updated_by` is the restoring admin subject the handler stamps on
/// trust records (`None` in the offline check, which has no actor).
pub(crate) fn admit_restore_payload(
    mut payload: RestorePayload,
    namespace: &str,
    provisioner: Option<&str>,
    trust_updated_by: Option<&str>,
    policy: &RestoreAdmissionPolicy,
) -> Result<AdmittedRestore, RestoreAdmissionError> {
    super::provisioning::stamp_resources(
        &mut payload.proxies,
        &mut payload.consumers,
        &mut payload.upstreams,
        &mut payload.plugin_configs,
        provisioner,
        true,
    );

    if !payload.version.is_empty()
        && payload.version != crate::config::types::CURRENT_CONFIG_VERSION
    {
        return Err(RestoreAdmissionError::Invalid(format!(
            "Incompatible config version '{}'. This gateway expects version '{}'",
            payload.version,
            crate::config::types::CURRENT_CONFIG_VERSION
        )));
    }

    let missing_id_errors = restore_missing_resource_id_errors(&payload);
    if !missing_id_errors.is_empty() {
        return Err(RestoreAdmissionError::Validation(missing_id_errors));
    }

    // Normalize the actual restore payload once, then validate that same
    // canonical instance. SQL and Mongo batch writers persist the values they
    // receive without repeating domain normalization.
    let mut candidate = GatewayConfig {
        version: crate::config::types::CURRENT_CONFIG_VERSION.to_string(),
        proxies: std::mem::take(&mut payload.proxies),
        consumers: std::mem::take(&mut payload.consumers),
        plugin_configs: std::mem::take(&mut payload.plugin_configs),
        upstreams: std::mem::take(&mut payload.upstreams),
        loaded_at: crate::time_compat::UtcTimestamp::now(),
        known_namespaces: Vec::new(),
        mesh: policy.mesh.clone(),
        ..Default::default()
    };
    candidate.normalize_fields();
    for proxy in &mut candidate.proxies {
        proxy.namespace = namespace.to_string();
    }
    for consumer in &mut candidate.consumers {
        consumer.namespace = namespace.to_string();
    }
    for plugin_config in &mut candidate.plugin_configs {
        plugin_config.namespace = namespace.to_string();
    }
    for upstream in &mut candidate.upstreams {
        upstream.namespace = namespace.to_string();
    }

    let mut validation_errors = super::restore_candidate_validation_errors(
        &mut candidate,
        policy.cert_expiry_days,
        &policy.backend_allow_ips,
    );
    // Restore replaces the whole namespace, so the candidate is authoritative
    // for mTLS transport compatibility (issue #4282).
    if let Err(errors) = candidate.validate_mtls_auth_compatibility() {
        validation_errors.extend(errors);
    }
    let http_client = match policy.plugin_http_client.clone() {
        Ok(client) => client,
        Err(error) => return Err(RestoreAdmissionError::Unavailable(error)),
    };
    // Plugin names and definitions are validated even for `enabled: false`
    // rows, matching `POST /batch` and single-resource admission (#4283).
    super::collect_plugin_config_admission_errors_with(
        &http_client,
        &policy.backend_allow_ips,
        &candidate.plugin_configs,
        &mut validation_errors,
    );
    match super::crud::validate_candidate_plugin_graph(&candidate, &http_client) {
        Ok(()) => {}
        Err(
            super::crud::AfterValidateError::BadRequest(errors)
            | super::crud::AfterValidateError::Conflict(errors),
        ) => validation_errors.extend(errors),
        Err(super::crud::AfterValidateError::Db(error)) => {
            return Err(RestoreAdmissionError::Unavailable(error.to_string()));
        }
        Err(super::crud::AfterValidateError::Response(_)) => validation_errors
            .push("Plugin-graph candidate validation returned an unexpected response".to_string()),
    }
    if !validation_errors.is_empty() {
        return Err(RestoreAdmissionError::Validation(validation_errors));
    }

    payload.proxies = candidate.proxies;
    payload.consumers = candidate.consumers;
    payload.plugin_configs = candidate.plugin_configs;
    payload.upstreams = candidate.upstreams;

    // Gateway trust bundles: forced into the target namespace, attributed to
    // the restoring subject, revision reset, and validated before anything is
    // deleted (issue #3727). The resource is a namespace singleton.
    if let Some(records) = payload.gateway_trust_bundles.as_mut() {
        let mut trust_errors = Vec::new();
        if records.len() > 1 {
            trust_errors
                .push(super::GATEWAY_TRUST_BUNDLE_RESTORE_NOT_SINGLETON_MESSAGE.to_string());
        }
        for record in records.iter_mut() {
            record.namespace = namespace.to_string();
            record.updated_by = trust_updated_by.map(str::to_string);
            record.revision = 0;
            record.normalize_fields();
            if let Err(errors) = record.validate_fields() {
                trust_errors.extend(errors);
            }
        }
        if !trust_errors.is_empty() {
            return Err(RestoreAdmissionError::Validation(trust_errors));
        }
    }

    // The versioned api_specs section, validated against the same canonical
    // resources that are later persisted, including each stored document's
    // extension admission. An absent section is decided by the handler: it
    // needs the target namespace's current spec count.
    let api_specs = match payload.api_specs.take() {
        Some(section) => match validate_restore_api_specs_section_with_total_limit(
            &section,
            &payload.proxies,
            &payload.upstreams,
            &payload.plugin_configs,
            policy.max_spec_body_mib,
            policy.max_total_spec_bytes,
        ) {
            Ok(mut specs) => {
                for spec in &mut specs {
                    spec.namespace = namespace.to_string();
                }
                Some(specs)
            }
            Err(errors) => return Err(RestoreAdmissionError::Validation(errors)),
        },
        None => None,
    };

    let section = payload.namespace_registry.take();
    let namespace_registry_present = section.is_some();
    let namespace_registry_description = match section {
        Some(section) => {
            let description = admit_namespace_registry_section(&section)?;
            (section.name == namespace).then_some(description)
        }
        None => None,
    };

    Ok(AdmittedRestore {
        payload,
        api_specs,
        namespace_registry_description,
        namespace_registry_present,
    })
}

fn admit_namespace_registry_section(
    section: &NamespaceRegistryBackupSection,
) -> Result<Option<String>, RestoreAdmissionError> {
    section.admit().map_err(RestoreAdmissionError::Validation)
}

/// `ferrum-edge validate --backup` (issue #7532): read a `GET /backup` export
/// under the restore body limit and run [`admit_restore_payload`] over it with
/// the policy the same environment gives the restore handler. Returns what it
/// would restore, or every refusal message. Makes no database connection.
pub(crate) fn check_backup_export(
    path: &std::path::Path,
    env_config: &crate::config::EnvConfig,
    serves_proxy: bool,
) -> Result<RestoreSummary, Vec<String>> {
    let policy = RestoreAdmissionPolicy::from_env_config(env_config, serves_proxy);
    check_backup_file(
        path,
        &env_config.namespace,
        env_config.admin_restore_max_body_size_mib,
        &policy,
    )
}

/// The file half of [`check_backup_export`], for an explicit policy.
pub(crate) fn check_backup_file(
    path: &std::path::Path,
    namespace: &str,
    restore_max_body_mib: usize,
    policy: &RestoreAdmissionPolicy,
) -> Result<RestoreSummary, Vec<String>> {
    use crate::config::stable_file::{StableFileError, StableFileReadOptions, read_stable_file};

    let limit = restore_max_body_bytes(restore_max_body_mib);
    let body = read_stable_file(
        path,
        StableFileReadOptions::new(u64::try_from(limit).unwrap_or(u64::MAX), "backup export"),
    )
    .map_err(|error| {
        vec![match error {
            StableFileError::NotFound => {
                "backup export not found: no file exists at the --backup path".to_string()
            }
            StableFileError::TooLarge { .. } => format!(
                "backup export exceeds the POST /restore body limit of {restore_max_body_mib} MiB \
                 (`FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB`)"
            ),
            other => format!("backup export could not be read: {other}"),
        }]
    })?;
    let payload = parse_restore_payload(body.as_bytes()).map_err(|error| error.messages())?;
    admit_restore_payload(payload, namespace, None, None, policy)
        .map(|admitted| admitted.summary())
        .map_err(|error| error.messages())
}

/// The offline check's policy for an explicit environment slice (tests use
/// it to mirror a test `AdminState` without process-environment mutation).
pub(crate) fn offline_policy_for_test(
    backend_allow_ips: BackendEgressPolicy,
    max_spec_body_mib: usize,
    restore_max_body_mib: usize,
) -> RestoreAdmissionPolicy {
    RestoreAdmissionPolicy {
        cert_expiry_days: crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS,
        plugin_http_client: crate::config::CompressionAdmissionPolicy::from_process_env().map(
            |compression_policy| {
                crate::plugins::PluginHttpClient::default_with_backend_allow_ips(
                    backend_allow_ips.clone(),
                )
                .with_real_ip_header(crate::config::env_config::resolve_real_ip_header())
                .with_compression_admission_policy(compression_policy)
            },
        ),
        backend_allow_ips,
        mesh: None,
        max_spec_body_mib,
        max_total_spec_bytes: restore_max_body_bytes(restore_max_body_mib),
    }
}
