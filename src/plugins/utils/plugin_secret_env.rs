//! Shared resolver for plugin-config references to process environment secrets.
//!
//! Plugin configs are written through the admin API by principals that do not
//! own the gateway process environment (the `operator` role, CP tenants, mesh
//! policy authors). Several plugins let that config NAME an environment
//! variable whose value is then sent as a credential to an endpoint the same
//! config chooses. Without a boundary that turns a config write into a read of
//! every process secret — the admin JWT secret, database URLs, cloud
//! credentials — delivered to a host the writer controls.
//!
//! The boundary is a dedicated namespace: a plugin config may reference only
//! `FERRUM_PLUGIN_SECRET_<NAME>`, where `<NAME>` is uppercase
//! `[A-Z_][A-Z0-9_]*`. Only whoever controls the process environment can
//! populate that namespace, so placing a value there is the explicit operator
//! decision that plugin configs may use it. Every other variable — including
//! every other `FERRUM_*` setting — is refused at admission, before any value
//! is read.
//!
//! The namespace is under `FERRUM_`, so startup external-secret resolution
//! applies: `FERRUM_PLUGIN_SECRET_<NAME>_FILE` / `_VAULT` / `_AWS` / `_AZURE` /
//! `_GCP` materialize `FERRUM_PLUGIN_SECRET_<NAME>` before any plugin reads it.
//!
//! Diagnostics never echo the referenced name or its value: a hostile config
//! can put an arbitrary string in the reference field.

/// Prefix every plugin-config environment reference must carry.
pub const PLUGIN_SECRET_ENV_PREFIX: &str = "FERRUM_PLUGIN_SECRET_";

/// Upper bound on a reference name, checked before any byte walk.
pub const MAX_PLUGIN_SECRET_ENV_NAME_BYTES: usize = 256;

/// True when `name` is an admissible plugin-config environment reference.
pub fn is_plugin_secret_env_name(name: &str) -> bool {
    if name.len() > MAX_PLUGIN_SECRET_ENV_NAME_BYTES {
        return false;
    }
    let Some(suffix) = name.strip_prefix(PLUGIN_SECRET_ENV_PREFIX) else {
        return false;
    };
    let mut bytes = suffix.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first.is_ascii_uppercase())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

/// Admission check for a configured reference. `field` is the schema label
/// used in the diagnostic (for example ``"api_chargeback_sink: `clickhouse.password_ref`"``).
pub fn validate_plugin_secret_env_name(field: &str, name: &str) -> Result<(), String> {
    if is_plugin_secret_env_name(name) {
        return Ok(());
    }
    Err(format!(
        "{field} must name a `{PLUGIN_SECRET_ENV_PREFIX}<NAME>` environment variable \
         (`<NAME>` is uppercase [A-Z_][A-Z0-9_]*); plugin configs cannot reference any other \
         process environment variable"
    ))
}

/// Resolve a configured reference against the process environment.
///
/// Re-checks the name first so a caller that skipped admission still cannot
/// read outside the namespace. An unset, empty, or non-UTF-8 value is an
/// error: a plugin must never send an empty or substituted credential.
pub fn resolve_plugin_secret_env(field: &str, name: &str) -> Result<String, String> {
    validate_plugin_secret_env_name(field, name)?;
    let problem = match std::env::var(name) {
        Ok(value) if !value.is_empty() => return Ok(value),
        Ok(_) => "is set but empty",
        Err(std::env::VarError::NotPresent) => "is not set",
        Err(std::env::VarError::NotUnicode(_)) => "does not hold valid UTF-8",
    };
    Err(format!(
        "{field} references a `{PLUGIN_SECRET_ENV_PREFIX}<NAME>` env variable that {problem}"
    ))
}
