//! HashiCorp Vault secret resolution (requires `secrets-vault` feature).

use std::env;

/// Check if the `{key}_VAULT` env var is set and non-empty.
/// Returns the Vault path reference (e.g. `secret/data/gateway#field`) if so.
pub fn resolve_ref(key: &str) -> Option<String> {
    let vault_key = format!("{}_VAULT", key);
    env::var(&vault_key).ok().filter(|s| !s.is_empty())
}

/// Opt-in that lets `VAULT_ADDR` use plaintext `http` for a non-loopback host.
///
/// Read from the process environment only, like `VAULT_ADDR` and `VAULT_TOKEN`
/// themselves: Vault client construction runs during startup secret resolution,
/// before `ferrum.conf` is loaded.
const ALLOW_PLAINTEXT_ENV: &str = "FERRUM_VAULT_ALLOW_PLAINTEXT";

/// Refuse plaintext Vault traffic that leaves the host (issue #6582).
///
/// Every Vault request carries `VAULT_TOKEN` in `X-Vault-Token` and every
/// response carries a secret, so `http` to a remote host hands both to any
/// on-path observer. `https` is always accepted. `http` is accepted for a
/// loopback host (`localhost`, `127.0.0.0/8`, `::1`, or an IPv4-mapped
/// loopback), where a local agent or dev server never puts the token on the
/// network, and otherwise only when [`ALLOW_PLAINTEXT_ENV`] is `true`.
///
/// Diagnostics name the variables and the failure class only, never the
/// address, so userinfo or a sensitive host name cannot leak through them.
fn check_plaintext_policy(
    addr: &url::Url,
    allow_plaintext: Option<&str>,
) -> Result<(), String> {
    let allow = match allow_plaintext.map(str::trim) {
        None | Some("") => false,
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => true,
            "false" | "0" | "no" => false,
            _ => return Err(format!("{ALLOW_PLAINTEXT_ENV} must be true or false")),
        },
    };
    if addr.scheme() != "http" || host_is_loopback(addr) {
        return Ok(());
    }
    if !allow {
        return Err(format!(
            "VAULT_ADDR must use https for a non-loopback Vault host: plaintext http would \
             send VAULT_TOKEN and every fetched secret unencrypted. Use https, or set \
             {ALLOW_PLAINTEXT_ENV}=true to accept plaintext Vault traffic"
        ));
    }
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            "VAULT_ADDR uses plaintext http to a non-loopback host because \
             {ALLOW_PLAINTEXT_ENV}=true; VAULT_TOKEN and fetched secrets cross the network \
             unencrypted"
        );
    });
    Ok(())
}

fn host_is_loopback(addr: &url::Url) -> bool {
    match addr.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        None => false,
    }
}

/// Reusable Vault client for batch secret resolution.
/// Created once and shared across multiple Vault secret fetches.
pub struct VaultClientWrapper {
    client: vaultrs::client::VaultClient,
}

impl VaultClientWrapper {
    /// Create a new Vault client from standard env vars (`VAULT_ADDR`, `VAULT_TOKEN`).
    pub fn new() -> Result<Self, String> {
        let vault_addr = env::var("VAULT_ADDR")
            .map_err(|_| "VAULT_ADDR must be set to resolve secrets from Vault".to_string())?;
        let vault_token = env::var("VAULT_TOKEN")
            .map_err(|_| "VAULT_TOKEN must be set to resolve secrets from Vault".to_string())?;

        let parsed_addr = url::Url::parse(&vault_addr)
            .map_err(|e| format!("VAULT_ADDR is not a valid URL: {e}"))?;
        if !matches!(parsed_addr.scheme(), "http" | "https") {
            return Err("VAULT_ADDR must use http or https".to_string());
        }
        check_plaintext_policy(&parsed_addr, env::var(ALLOW_PLAINTEXT_ENV).ok().as_deref())?;

        let mut settings_builder = vaultrs::client::VaultClientSettingsBuilder::default();
        // vaultrs 0.8's address setter panics on parse failure. A serialized
        // Url reparses successfully; never pass the unchecked environment value.
        // Parse diagnostics above contain only the failure class, not credentials.
        settings_builder
            .address(parsed_addr.as_str())
            .token(&vault_token);

        if let Ok(ca_path) = env::var("FERRUM_TLS_CA_BUNDLE_PATH")
            && !ca_path.is_empty()
        {
            settings_builder.ca_certs(vec![ca_path]);
        }

        let settings = settings_builder
            .build()
            .map_err(|e| format!("Failed to build Vault client settings: {}", e))?;

        let client = vaultrs::client::VaultClient::new(settings)
            .map_err(|e| format!("Failed to create Vault client: {}", e))?;

        Ok(Self { client })
    }

    /// Fetch a secret value from Vault using this client.
    pub async fn fetch_secret(&self, reference: &str, key: &str) -> Result<String, String> {
        fetch_with_client(&self.client, reference, key).await
    }
}

/// Fetch a single secret from Vault (creates a new client).
/// For batch resolution, use `VaultClientWrapper`.
pub async fn fetch_secret(reference: &str, key: &str) -> Result<String, String> {
    let wrapper = VaultClientWrapper::new()?;
    wrapper.fetch_secret(reference, key).await
}

/// Shared fetch logic used by both single and batch paths.
async fn fetch_with_client(
    client: &vaultrs::client::VaultClient,
    reference: &str,
    key: &str,
) -> Result<String, String> {
    // Parse the reference: path#json_key
    let (path, json_key) = super::split_reference_field(reference);

    // Parse mount and path from the reference
    // Format: <mount>/data/<secret_path> (KV v2 convention)
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    if parts.len() < 3 || parts[1] != "data" {
        return Err(format!(
            "Invalid Vault KV v2 reference for {}. \
             Expected format: <mount>/data/<path>#<json_key>",
            key
        ));
    }
    let mount = parts[0];
    let secret_path = parts[2];

    // Errors name the base key and the failure class only. The Vault path and
    // JSON field are part of the source reference, which is as sensitive as the
    // value it points at; the registry additionally redacts any residual
    // occurrence that leaks out of `vaultrs` itself.
    let secret: std::collections::HashMap<String, String> =
        vaultrs::kv2::read(client, mount, secret_path)
            .await
            .map_err(|e| format!("Failed to read {} from Vault: {}", key, e))?;

    match json_key {
        Some(jk) => secret.get(jk).cloned().ok_or_else(|| {
            format!(
                "Vault secret for {} does not contain the requested key",
                key
            )
        }),
        None => {
            // Without an explicit #json_key, require exactly one key to avoid
            // non-deterministic results from HashMap iteration order.
            if secret.len() != 1 {
                return Err(format!(
                    "Vault secret for {} contains {} keys — \
                     specify which key to use with #<json_key> suffix",
                    key,
                    secret.len()
                ));
            }
            secret
                .into_values()
                .next()
                .ok_or_else(|| format!("Vault secret for {} is empty", key))
        }
    }
}
