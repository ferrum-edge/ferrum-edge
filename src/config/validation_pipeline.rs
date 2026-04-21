use crate::config::BackendAllowIps;
use crate::config::types::GatewayConfig;
use tracing::{error, warn};

pub(crate) enum ValidationAction<'a> {
    Collect,
    Warn,
    FatalCount(&'a str),
    FatalStatic(&'a str),
}

enum ValidationStep<'a> {
    NormalizeFields,
    ResolveUpstreamTls,
    ResourceIds {
        action: ValidationAction<'a>,
    },
    AllFieldsWithIpPolicy {
        cert_expiry_warning_days: u64,
        backend_allow_ips: &'a BackendAllowIps,
        action: ValidationAction<'a>,
    },
    AllFields {
        cert_expiry_warning_days: u64,
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
    PluginReferences {
        action: ValidationAction<'a>,
    },
    PluginConfigs {
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
        backend_allow_ips: &'a BackendAllowIps,
        action: ValidationAction<'a>,
    ) -> Self {
        self.steps.push(ValidationStep::AllFieldsWithIpPolicy {
            cert_expiry_warning_days,
            backend_allow_ips,
            action,
        });
        self
    }

    pub(crate) fn validate_all_fields(
        mut self,
        cert_expiry_warning_days: u64,
        action: ValidationAction<'a>,
    ) -> Self {
        self.steps.push(ValidationStep::AllFields {
            cert_expiry_warning_days,
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

    pub(crate) fn validate_plugin_references(mut self, action: ValidationAction<'a>) -> Self {
        self.steps.push(ValidationStep::PluginReferences { action });
        self
    }

    pub(crate) fn validate_plugin_configs(mut self, action: ValidationAction<'a>) -> Self {
        self.steps.push(ValidationStep::PluginConfigs { action });
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
    /// (`FatalCount` or `FatalStatic`) fires. At that point the pipeline bails
    /// immediately and any previously collected warnings/errors are discarded in
    /// favor of the fatal summary, matching the original call-site behavior.
    pub(crate) fn run(self) -> Result<Vec<String>, anyhow::Error> {
        let ValidationPipeline { config, steps } = self;
        let mut collected_errors = Vec::new();

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
                ValidationStep::AllFields {
                    cert_expiry_warning_days,
                    action,
                } => {
                    if let Err(errors) = config.validate_all_fields(cert_expiry_warning_days) {
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
                ValidationStep::PluginReferences { action } => {
                    if let Err(errors) = config.validate_plugin_references() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::PluginConfigs { action } => {
                    let mut errors = Vec::new();
                    for plugin_config in &config.plugin_configs {
                        if !plugin_config.enabled {
                            continue;
                        }
                        if let Err(err) = crate::plugins::validate_plugin_config(
                            &plugin_config.plugin_name,
                            &plugin_config.config,
                        ) {
                            errors.push(format!(
                                "Plugin '{}' (id={}): {}",
                                plugin_config.plugin_name, plugin_config.id, err
                            ));
                        }
                    }
                    if !errors.is_empty() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::PluginFileDependencies { action } => {
                    let errors = config.validate_plugin_file_dependencies();
                    if !errors.is_empty() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
                ValidationStep::StreamProxies { action } => {
                    if let Err(errors) = config.validate_stream_proxies() {
                        handle_validation_errors(action, errors, &mut collected_errors)?;
                    }
                }
            }
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
        ValidationAction::FatalStatic(summary) => {
            for message in &errors {
                error!("{}", message);
            }
            anyhow::bail!(summary.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ValidationAction, handle_validation_errors};

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
    fn fatal_static_action_returns_verbatim_summary() {
        let mut collected = Vec::new();

        let err = handle_validation_errors(
            ValidationAction::FatalStatic("Static summary"),
            vec!["a".to_string()],
            &mut collected,
        )
        .unwrap_err();

        assert_eq!(err.to_string(), "Static summary");
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
        handle_validation_errors(
            ValidationAction::FatalStatic("unused"),
            Vec::new(),
            &mut collected,
        )
        .unwrap();

        assert_eq!(collected, vec!["existing"]);
    }
}
