use crate::config::BackendEgressPolicy;
use crate::config::types::{CountryMmdbValidationGeneration, GatewayConfig};
use tracing::{error, warn};

pub(crate) enum ValidationAction<'a> {
    Collect,
    Warn,
    FatalCount(&'a str),
}

enum ValidationStep<'a> {
    NormalizeFields,
    ResolveUpstreamTls,
    ResourceIds {
        action: ValidationAction<'a>,
    },
    AllFieldsWithIpPolicy {
        cert_expiry_warning_days: u64,
        backend_allow_ips: &'a BackendEgressPolicy,
        action: ValidationAction<'a>,
    },
    UniqueResourceIds {
        action: ValidationAction<'a>,
    },
    Hosts {
        action: ValidationAction<'a>,
    },
    RegexListenPaths {
        action: ValidationAction<'a>,
    },
    ListenPathEncodings {
        action: ValidationAction<'a>,
    },
    UniqueListenPaths {
        action: ValidationAction<'a>,
    },
    UniqueConsumerIdentities {
        action: ValidationAction<'a>,
    },
    UniqueConsumerCredentials {
        action: ValidationAction<'a>,
    },
    UniqueUpstreamNames {
        action: ValidationAction<'a>,
    },
    UniqueProxyNames {
        action: ValidationAction<'a>,
    },
    UpstreamReferences {
        action: ValidationAction<'a>,
    },
    MeshRouteDispatchReferences {
        action: ValidationAction<'a>,
    },
    PluginReferences {
        action: ValidationAction<'a>,
    },
    PluginConfigs {
        backend_allow_ips: &'a BackendEgressPolicy,
        action: ValidationAction<'a>,
    },
    PluginFileDependencies {
        action: ValidationAction<'a>,
    },
    StreamProxies {
        action: ValidationAction<'a>,
    },
}

pub(crate) struct ValidationPipeline<'a> {
    config: &'a mut GatewayConfig,
    steps: Vec<ValidationStep<'a>>,
}

/// Run the potentially large MMDB read, verification, and full-record scan on
/// Tokio's blocking pool. Async database and reload paths pass ownership of the
/// candidate config through this helper so runtime workers never perform the
/// synchronous node-local dependency work.
pub(crate) async fn validate_plugin_file_dependencies_off_thread(
    mut config: GatewayConfig,
    action: ValidationAction<'static>,
) -> Result<GatewayConfig, anyhow::Error> {
    tokio::task::spawn_blocking(move || -> Result<GatewayConfig, anyhow::Error> {
        ValidationPipeline::new(&mut config)
            .validate_plugin_file_dependencies(action)
            .run()?;
        Ok(config)
    })
    .await
    .map_err(|error| anyhow::anyhow!("MaxMind database validation worker failed: {error}"))?
}

/// Collect the rejecting runtime-config validation contract shared by
/// database full loads and CP incremental updates.
///
/// Warning-only validation (for example certificate paths and exact consumer
/// identity collisions) remains mode-specific and is intentionally excluded.
pub(crate) fn collect_rejecting_runtime_config_errors(config: &GatewayConfig) -> Vec<String> {
    let mut errors = Vec::new();

    if let Err(found) = config.validate_regex_listen_paths() {
        errors.extend(found);
    }
    if let Err(found) = config.validate_listen_path_encodings() {
        errors.extend(found);
    }
    if let Err(found) = config.validate_unique_listen_paths() {
        errors.extend(found);
    }
    if let Err(found) = config.validate_stream_proxies() {
        errors.extend(found);
    }
    if let Err(found) = config.validate_upstream_references() {
        errors.extend(found);
    }
    if let Err(found) = config.validate_plugin_references() {
        errors.extend(found);
    }
    if let Err(found) = crate::plugins::transaction_log_schema::validate_config_graph(
        config,
        &crate::plugins::PluginHttpClient::default().with_process_compression_admission_policy(),
        false,
    ) {
        errors.extend(found);
    }
    // Serving modes reject malformed fail-closed plugins while staging the
    // PluginCache. CP mode has no runtime PluginCache, so validate the
    // security-critical ip_restriction and geo_restriction shapes here as well
    // before a database snapshot or delta can be accepted and broadcast. This
    // intentionally invokes the same side-effect-free validators used by
    // file/admin/DP admission rather than duplicating their allowed-key
    // contracts. Geo shape validation never opens its node-local MMDB.
    //
    // Do not generalize this from PluginFailurePolicy::FailClosed alone. That
    // policy describes data-plane cache publication, not a pure CP schema
    // contract: some registered constructors intentionally depend on node-local
    // resources, while adaptive_concurrency requires gateway/cache state.
    // Broader CP parity needs explicit shape-only validators and mode/resource
    // contracts for each such plugin.
    for plugin_config in &config.plugin_configs {
        if !plugin_config.enabled {
            continue;
        }
        let shape_error = match plugin_config.plugin_name.as_str() {
            "ip_restriction" => {
                crate::plugins::ip_restriction::IpRestriction::new(&plugin_config.config)
                    .map(|_| ())
            }
            "geo_restriction" => crate::plugins::geo_restriction::GeoRestriction::validate_config(
                &plugin_config.config,
            ),
            _ => continue,
        };
        if let Err(error) = shape_error {
            errors.push(format!(
                "Plugin '{}' (id={}): {error}",
                plugin_config.plugin_name, plugin_config.id
            ));
        }
    }
    if let Err(found) = crate::plugin_cache::validate_plugin_security_composition_candidate(
        config,
        &crate::plugins::PluginHttpClient::default()
            .with_real_ip_header(crate::config::env_config::resolve_real_ip_header())
            .with_process_compression_admission_policy(),
    ) {
        errors.push(found);
    }
    if let Err(found) = crate::plugin_cache::validate_tcp_connection_throttle_attachments(config) {
        errors.extend(found);
    }
    if let Err(found) = config.validate_unique_mtls_dns_identities() {
        errors.extend(found);
    }
    if let Err(found) = crate::proxy::validate_mesh_route_dispatch_upstream_references(config) {
        errors.extend(found);
    }

    errors
}

/// Marker error distinguishing a config-VALIDATION rejection — the loaded
/// snapshot was reachable but is semantically invalid per
/// [`collect_rejecting_runtime_config_errors`] — from a connectivity/driver
/// failure.
///
/// Both full and incremental database loads return this (wrapped in
/// `anyhow::Error`) when a reachable backend yields an invalid config snapshot.
/// It is downcast-discoverable through `anyhow` so the database-mode poll loop
/// can keep `db_available = true` (the backend is reachable and admin writes
/// are the in-band repair tool) on a validation rejection, while still
/// returning `Err` so runtime caches and CP broadcast never rebuild from a
/// rejected snapshot. A genuine connectivity error carries no such marker and
/// keeps the fail-closed `db_available = false` behavior.
#[derive(Debug)]
pub(crate) struct ConfigValidationRejection {
    /// Backend label for logging (e.g. `"MongoDB"` / `"Database"`).
    pub backend: &'static str,
    /// The individual rejecting validation messages.
    pub errors: Vec<String>,
}

impl std::fmt::Display for ConfigValidationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} configuration validation failed: {} rejecting error(s) found",
            self.backend,
            self.errors.len()
        )
    }
}

impl std::error::Error for ConfigValidationRejection {}

impl ConfigValidationRejection {
    /// Build the `anyhow::Error` a loader returns on a validation rejection.
    pub(crate) fn into_anyhow(self) -> anyhow::Error {
        anyhow::Error::new(self)
    }
}

/// Returns `true` when any link in the error chain is a
/// [`ConfigValidationRejection`] — i.e. the load failed because a reachable
/// snapshot was semantically invalid, not because the backend was unreachable.
pub(crate) fn is_config_validation_rejection(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.is::<ConfigValidationRejection>())
}

impl<'a> ValidationPipeline<'a> {
    pub(crate) fn new(config: &'a mut GatewayConfig) -> Self {
        Self {
            config,
            steps: Vec::new(),
        }
    }

    pub(crate) fn normalize_fields(mut self) -> Self {
        self.steps.push(ValidationStep::NormalizeFields);
        self
    }

    pub(crate) fn resolve_upstream_tls(mut self) -> Self {
        self.steps.push(ValidationStep::ResolveUpstreamTls);
        self
    }

    pub(crate) fn validate_resource_ids(mut self, action: ValidationAction<'a>) -> Self {
        self.steps.push(ValidationStep::ResourceIds { action });
        self
    }

    pub(crate) fn validate_all_fields_with_ip_policy(
        mut self,
        cert_expiry_warning_days: u64,
        backend_allow_ips: &'a BackendEgressPolicy,
        action: ValidationAction<'a>,
    ) -> Self {
        self.steps.push(ValidationStep::AllFieldsWithIpPolicy {
            cert_expiry_warning_days,
            backend_allow_ips,
            action,
        });
        self
    }

    pub(crate) fn validate_unique_resource_ids(mut self, action: ValidationAction<'a>) -> Self {
        self.steps
            .push(ValidationStep::UniqueResourceIds { action });
        self
    }

    pub(crate) fn validate_hosts(mut self, action: ValidationAction<'a>) -> Self {
        self.steps.push(ValidationStep::Hosts { action });
        self
    }

    pub(crate) fn validate_regex_listen_paths(mut self, action: ValidationAction<'a>) -> Self {
        self.steps.push(ValidationStep::RegexListenPaths { action });
        self
    }

    pub(crate) fn validate_listen_path_encodings(mut self, action: ValidationAction<'a>) -> Self {
        self.steps
            .push(ValidationStep::ListenPathEncodings { action });
        self
    }

    pub(crate) fn validate_unique_listen_paths(mut self, action: ValidationAction<'a>) -> Self {
        self.steps
            .push(ValidationStep::UniqueListenPaths { action });
        self
    }

    pub(crate) fn validate_unique_consumer_identities(
        mut self,
        action: ValidationAction<'a>,
    ) -> Self {
        self.steps
            .push(ValidationStep::UniqueConsumerIdentities { action });
        self
    }

    pub(crate) fn validate_unique_consumer_credentials(
        mut self,
        action: ValidationAction<'a>,
    ) -> Self {
        self.steps
            .push(ValidationStep::UniqueConsumerCredentials { action });
        self
    }

    pub(crate) fn validate_unique_upstream_names(mut self, action: ValidationAction<'a>) -> Self {
        self.steps
            .push(ValidationStep::UniqueUpstreamNames { action });
        self
    }

    pub(crate) fn validate_unique_proxy_names(mut self, action: ValidationAction<'a>) -> Self {
        self.steps.push(ValidationStep::UniqueProxyNames { action });
        self
    }

    pub(crate) fn validate_upstream_references(mut self, action: ValidationAction<'a>) -> Self {
        self.steps
            .push(ValidationStep::UpstreamReferences { action });
        self
    }

    pub(crate) fn validate_mesh_route_dispatch_references(
        mut self,
        action: ValidationAction<'a>,
    ) -> Self {
        self.steps
            .push(ValidationStep::MeshRouteDispatchReferences { action });
        self
    }

    pub(crate) fn validate_plugin_references(mut self, action: ValidationAction<'a>) -> Self {
        self.steps.push(ValidationStep::PluginReferences { action });
        self
    }

    pub(crate) fn validate_plugin_configs(
        mut self,
        backend_allow_ips: &'a BackendEgressPolicy,
        action: ValidationAction<'a>,
    ) -> Self {
        self.steps.push(ValidationStep::PluginConfigs {
            backend_allow_ips,
            action,
        });
        self
    }

    pub(crate) fn validate_plugin_file_dependencies(
        mut self,
        action: ValidationAction<'a>,
    ) -> Self {
        self.steps
            .push(ValidationStep::PluginFileDependencies { action });
        self
    }

    pub(crate) fn validate_stream_proxies(mut self, action: ValidationAction<'a>) -> Self {
        self.steps.push(ValidationStep::StreamProxies { action });
        self
    }

    /// Execute each validation step in insertion order.
    ///
    /// `Collect` steps append into the returned vector until a fatal action
    /// (`FatalCount`) fires. At that point the pipeline bails
    /// immediately and any previously collected warnings/errors are discarded in
    /// favor of the fatal summary, matching the original call-site behavior.
    pub(crate) fn run(self) -> Result<Vec<String>, anyhow::Error> {
        let ValidationPipeline { config, steps } = self;
        let mut collected_errors = Vec::new();
        let mut country_mmdb_validation_generation = None;

        for step in steps {
            match step {
                ValidationStep::NormalizeFields => config.normalize_fields(),
                ValidationStep::ResolveUpstreamTls => config.resolve_upstream_tls(),
                ValidationStep::ResourceIds { action } => {
                    if let Err(errors) = config.validate_resource_ids() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::AllFieldsWithIpPolicy {
                    cert_expiry_warning_days,
                    backend_allow_ips,
                    action,
                } => {
                    if let Err(errors) = config.validate_all_fields_with_ip_policy(
                        cert_expiry_warning_days,
                        backend_allow_ips,
                    ) {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::UniqueResourceIds { action } => {
                    if let Err(errors) = config.validate_unique_resource_ids() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::Hosts { action } => {
                    if let Err(errors) = config.validate_hosts() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::RegexListenPaths { action } => {
                    if let Err(errors) = config.validate_regex_listen_paths() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::ListenPathEncodings { action } => {
                    if let Err(errors) = config.validate_listen_path_encodings() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::UniqueListenPaths { action } => {
                    if let Err(errors) = config.validate_unique_listen_paths() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::UniqueConsumerIdentities { action } => {
                    if let Err(errors) = config.validate_unique_consumer_identities() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::UniqueConsumerCredentials { action } => {
                    if let Err(errors) = config.validate_unique_consumer_credentials() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::UniqueUpstreamNames { action } => {
                    if let Err(errors) = config.validate_unique_upstream_names() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::UniqueProxyNames { action } => {
                    if let Err(errors) = config.validate_unique_proxy_names() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::UpstreamReferences { action } => {
                    if let Err(errors) = config.validate_upstream_references() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::MeshRouteDispatchReferences { action } => {
                    if let Err(errors) =
                        crate::proxy::validate_mesh_route_dispatch_upstream_references(config)
                    {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::PluginReferences { action } => {
                    if let Err(errors) = config.validate_plugin_references() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::PluginConfigs {
                    backend_allow_ips,
                    action,
                } => {
                    let mut errors = Vec::new();
                    let graph_http_client =
                        crate::plugins::PluginHttpClient::default_with_backend_allow_ips(
                            backend_allow_ips.clone(),
                        )
                        .with_process_compression_admission_policy();
                    if let Err(graph_errors) =
                        crate::plugins::transaction_log_schema::validate_config_graph(
                            config,
                            &graph_http_client,
                            matches!(&action, ValidationAction::Collect),
                        )
                    {
                        errors.extend(graph_errors);
                    }
                    for plugin_config in &config.plugin_configs {
                        if !plugin_config.enabled {
                            continue;
                        }
                        // The prospective graph pass above validates schema
                        // definitions and referrers in definition-first order.
                        // Re-validating either one here would consult the live
                        // registry after the isolated bracket was aborted.
                        if crate::plugins::transaction_log_schema::participates_in_config_graph(
                            plugin_config,
                        ) {
                            if let Err(err) = crate::plugins::validate_plugin_config_policy_only(
                                &plugin_config.plugin_name,
                                &plugin_config.config,
                                backend_allow_ips,
                            ) {
                                let message = format!(
                                    "Plugin '{}' (id={}): {}",
                                    plugin_config.plugin_name, plugin_config.id, err
                                );
                                if !matches!(&action, ValidationAction::Collect)
                                    && crate::plugins::plugin_failure_policy(
                                        &plugin_config.plugin_name,
                                    ) == Some(
                                        crate::plugins::PluginFailurePolicy::OptionalFailOpen,
                                    )
                                {
                                    warn!("Optional plugin config validation warning: {}", message);
                                } else {
                                    errors.push(message);
                                }
                            }
                            continue;
                        }
                        if let Err(err) = crate::plugins::validate_plugin_config_with_policy(
                            &plugin_config.plugin_name,
                            &plugin_config.config,
                            backend_allow_ips,
                        ) {
                            let message = format!(
                                "Plugin '{}' (id={}): {}",
                                plugin_config.plugin_name, plugin_config.id, err
                            );
                            if !matches!(&action, ValidationAction::Collect)
                                && crate::plugins::plugin_failure_policy(&plugin_config.plugin_name)
                                    == Some(crate::plugins::PluginFailurePolicy::OptionalFailOpen)
                            {
                                warn!("Optional plugin config validation warning: {}", message);
                            } else {
                                errors.push(message);
                            }
                        }
                    }
                    if !errors.is_empty() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::PluginFileDependencies { action } => {
                    let country_mmdb_paths = config.country_mmdb_file_dependency_paths();
                    let generation = if country_mmdb_paths.is_empty() {
                        None
                    } else {
                        Some(
                            CountryMmdbValidationGeneration::begin(country_mmdb_paths)
                                .map_err(anyhow::Error::msg)?,
                        )
                    };
                    let errors = match generation.as_ref() {
                        Some(generation) => {
                            config.validate_plugin_file_dependencies_for_generation(generation)
                        }
                        None => config.validate_plugin_file_dependencies(),
                    };
                    if !errors.is_empty() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                    country_mmdb_validation_generation = generation;
                }
                ValidationStep::StreamProxies { action } => {
                    if let Err(errors) = config.validate_stream_proxies() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
            }
        }

        if let Some(generation) = country_mmdb_validation_generation {
            generation.commit().map_err(anyhow::Error::msg)?;
        }

        Ok(collected_errors)
    }
}

fn handle_validation_errors(
    action: ValidationAction<'_>,
    errors: Vec<String>,
    collected_errors: &mut Vec<String>,
) -> Result<(), anyhow::Error> {
    if errors.is_empty() {
        return Ok(());
    }

    match action {
        ValidationAction::Collect => {
            collected_errors.extend(errors);
            Ok(())
        }
        ValidationAction::Warn => {
            for message in &errors {
                warn!("{}", message);
            }
            Ok(())
        }
        ValidationAction::FatalCount(template) => {
            debug_assert!(
                template.contains("{}"),
                "FatalCount template must include a '{{}}' placeholder"
            );
            for message in &errors {
                error!("{}", message);
            }
            let summary = template.replacen("{}", &errors.len().to_string(), 1);
            anyhow::bail!(summary);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConfigValidationRejection, ValidationAction, ValidationPipeline,
        collect_rejecting_runtime_config_errors, handle_validation_errors,
        is_config_validation_rejection,
    };
    use crate::config::types::{
        GatewayConfig, PluginAssociation, PluginConfig, PluginScope, Proxy, default_namespace,
    };
    use chrono::Utc;
    use serde_json::json;

    fn runtime_proxy(id: &str, listen_path: Option<&str>, backend_scheme: &str) -> Proxy {
        serde_json::from_value(json!({
            "id": id,
            "listen_path": listen_path,
            "backend_scheme": backend_scheme,
            "backend_host": "localhost",
            "backend_port": 3000
        }))
        .expect("minimal runtime proxy should deserialize")
    }

    fn rejecting_errors(mut config: GatewayConfig) -> Vec<String> {
        config.normalize_fields();
        config.resolve_upstream_tls();
        collect_rejecting_runtime_config_errors(&config)
    }

    fn assert_single_rejecting_error(config: GatewayConfig, expected: &str) {
        let errors = rejecting_errors(config);
        assert_eq!(errors.len(), 1, "expected one rejecting error: {errors:?}");
        assert!(errors[0].contains(expected), "unexpected error: {errors:?}");
    }

    #[test]
    fn config_validation_rejection_is_downcast_discoverable_through_anyhow() {
        // Issue #2158: the database-mode poll loop must be able to tell a
        // validation rejection apart from a connectivity failure, even when the
        // error is wrapped with additional context on its way out of the loader.
        let err = ConfigValidationRejection {
            backend: "MongoDB",
            errors: vec!["dangling upstream reference".to_string()],
        }
        .into_anyhow();
        assert!(is_config_validation_rejection(&err));

        let wrapped = err.context("while polling authoritative primary");
        assert!(
            is_config_validation_rejection(&wrapped),
            "a context-wrapped rejection must still be discoverable"
        );
        assert!(
            wrapped.to_string().contains("while polling"),
            "context must be preserved"
        );
    }

    #[test]
    fn connectivity_error_is_not_a_config_validation_rejection() {
        let err = anyhow::anyhow!("connection refused (os error 61)");
        assert!(
            !is_config_validation_rejection(&err),
            "a plain connectivity error must NOT classify as a validation rejection"
        );
    }

    #[test]
    fn rejecting_runtime_contract_accepts_valid_config() {
        let config = GatewayConfig {
            proxies: vec![runtime_proxy("valid", Some("/valid"), "http")],
            ..Default::default()
        };

        assert!(rejecting_errors(config).is_empty());
    }

    #[test]
    fn rejecting_runtime_contract_includes_regex_listen_paths() {
        let config = GatewayConfig {
            proxies: vec![runtime_proxy("bad-regex", Some("~(invalid[regex"), "http")],
            ..Default::default()
        };

        assert_single_rejecting_error(config, "invalid regex listen_path");
    }

    #[test]
    fn rejecting_runtime_contract_includes_non_canonical_listen_paths() {
        let config = GatewayConfig {
            proxies: vec![runtime_proxy("encoded-slash", Some("/api%2Fadmin"), "http")],
            ..Default::default()
        };

        assert_single_rejecting_error(config, "canonical policy path");
    }

    #[test]
    fn rejecting_runtime_contract_includes_duplicate_listen_paths() {
        let config = GatewayConfig {
            proxies: vec![
                runtime_proxy("duplicate-a", Some("/duplicate"), "http"),
                runtime_proxy("duplicate-b", Some("/duplicate"), "http"),
            ],
            ..Default::default()
        };

        assert_single_rejecting_error(config, "Duplicate listen_path '/duplicate'");
    }

    #[test]
    fn rejecting_runtime_contract_includes_stream_proxy_shapes() {
        let config = GatewayConfig {
            proxies: vec![runtime_proxy("missing-port", None, "tcp")],
            ..Default::default()
        };

        assert_single_rejecting_error(config, "must have a listen_port");
    }

    #[test]
    fn rejecting_runtime_contract_includes_dangling_upstream_references() {
        let mut proxy = runtime_proxy("dangling-upstream", Some("/upstream"), "http");
        proxy.upstream_id = Some("missing-upstream".to_string());
        let config = GatewayConfig {
            proxies: vec![proxy],
            ..Default::default()
        };

        assert_single_rejecting_error(config, "non-existent upstream_id 'missing-upstream'");
    }

    #[test]
    fn rejecting_runtime_contract_includes_invalid_plugin_references() {
        let mut proxy = runtime_proxy("dangling-plugin", Some("/plugin"), "http");
        proxy.plugins = vec![PluginAssociation {
            plugin_config_id: "missing-plugin".to_string(),
        }];
        let config = GatewayConfig {
            proxies: vec![proxy],
            ..Default::default()
        };

        assert_single_rejecting_error(config, "non-existent plugin_config 'missing-plugin'");
    }

    #[test]
    fn rejecting_runtime_contract_includes_invalid_ip_restriction_shape() {
        let config = GatewayConfig {
            plugin_configs: vec![PluginConfig {
                id: "broadened-ip-policy".to_string(),
                namespace: default_namespace(),
                plugin_name: "ip_restriction".to_string(),
                config: json!({
                    "alow": ["10.0.0.0/8"],
                    "deny": ["192.0.2.0/24"]
                }),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }],
            ..Default::default()
        };

        assert_single_rejecting_error(config, "unknown configuration field 'alow'");
    }

    #[test]
    fn rejecting_runtime_contract_includes_invalid_geo_restriction_shape() {
        let config = GatewayConfig {
            plugin_configs: vec![PluginConfig {
                id: "broadened-geo-policy".to_string(),
                namespace: default_namespace(),
                plugin_name: "geo_restriction".to_string(),
                config: json!({
                    "db_path": "/data/GeoLite2-Country.mmdb",
                    "allow_countries": null,
                    "on_lookup_failure": "deny"
                }),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }],
            ..Default::default()
        };

        assert_single_rejecting_error(
            config,
            "'allow_countries' must be an array of ISO country codes",
        );
    }

    #[test]
    fn rejecting_runtime_contract_includes_mesh_dispatch_upstream_references() {
        let config = GatewayConfig {
            plugin_configs: vec![PluginConfig {
                id: "mesh-dispatch".to_string(),
                namespace: default_namespace(),
                plugin_name: "mesh_route_dispatch".to_string(),
                config: json!({
                    "rules": [{
                        "match": {"methods": ["GET"]},
                        "destination": {"upstream_id": "missing-mesh-upstream"}
                    }]
                }),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }],
            ..Default::default()
        };

        assert_single_rejecting_error(config, "upstream_id 'missing-mesh-upstream'");
    }

    #[test]
    fn collect_action_accumulates_errors() {
        let mut collected = vec!["existing".to_string()];

        handle_validation_errors(
            ValidationAction::Collect,
            vec!["first".to_string(), "second".to_string()],
            &mut collected,
        )
        .unwrap();

        assert_eq!(collected, vec!["existing", "first", "second"]);
    }

    #[test]
    fn warn_action_does_not_collect_or_fail() {
        let mut collected = vec!["existing".to_string()];

        handle_validation_errors(
            ValidationAction::Warn,
            vec!["warning".to_string()],
            &mut collected,
        )
        .unwrap();

        assert_eq!(collected, vec!["existing"]);
    }

    #[test]
    fn fatal_count_action_formats_error_count() {
        let mut collected = Vec::new();

        let err = handle_validation_errors(
            ValidationAction::FatalCount("Validation failed with {} errors"),
            vec!["a".to_string(), "b".to_string()],
            &mut collected,
        )
        .unwrap_err();

        assert_eq!(err.to_string(), "Validation failed with 2 errors");
        assert!(collected.is_empty());
    }

    #[test]
    fn empty_error_list_is_a_noop_for_all_actions() {
        let mut collected = vec!["existing".to_string()];

        handle_validation_errors(ValidationAction::Collect, Vec::new(), &mut collected).unwrap();
        handle_validation_errors(ValidationAction::Warn, Vec::new(), &mut collected).unwrap();
        handle_validation_errors(
            ValidationAction::FatalCount("unused {}"),
            Vec::new(),
            &mut collected,
        )
        .unwrap();
        assert_eq!(collected, vec!["existing"]);
    }

    #[test]
    fn collect_plugin_config_validation_keeps_optional_fail_open_errors() {
        let mut config = GatewayConfig {
            version: "1".to_string(),
            plugin_configs: vec![PluginConfig {
                id: "bad-stdout".to_string(),
                namespace: default_namespace(),
                plugin_name: "stdout_logging".to_string(),
                config: json!("bad-config"),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }],
            ..Default::default()
        };

        let errors = ValidationPipeline::new(&mut config)
            .validate_plugin_configs(
                &crate::config::BackendEgressPolicy::unrestricted(),
                ValidationAction::Collect,
            )
            .run()
            .expect("collect validation should return accumulated errors");

        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("stdout_logging"), "{errors:?}");
        assert!(errors[0].contains("bad-stdout"), "{errors:?}");
    }
}
