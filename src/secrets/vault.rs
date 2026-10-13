//! HashiCorp Vault secret resolution (requires `secrets-vault` feature).

use std::env;
use std::sync::atomic::{AtomicU8, Ordering};

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

/// Redirect hops a Vault request may follow, the same as reqwest's default.
const MAX_VAULT_REDIRECTS: usize = 10;

/// Parse [`ALLOW_PLAINTEXT_ENV`]. Unset or blank is `false`; a value that is
/// not a recognised boolean fails closed so a typo cannot read as either answer.
fn parse_allow_plaintext(raw: Option<&str>) -> Result<bool, String> {
    match raw.map(str::trim) {
        None | Some("") => Ok(false),
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(format!("{ALLOW_PLAINTEXT_ENV} must be true or false")),
        },
    }
}

/// Refuse plaintext Vault traffic that leaves the host (issue #6582).
///
/// Every Vault request carries `VAULT_TOKEN` in `X-Vault-Token` and every
/// response carries a secret, so `http` to a remote host hands both to any
/// on-path observer. `https` is always accepted. `http` is accepted for a
/// loopback host (`localhost`, `127.0.0.0/8`, `::1`, or an IPv4-mapped
/// loopback), where a local agent or dev server never puts the token on the
/// network, and otherwise only when [`ALLOW_PLAINTEXT_ENV`] is `true`. The
/// same rule follows every redirect, and a loopback `http` address bypasses
/// proxies (see [`vault_transport`]).
///
/// Diagnostics name the variables and the failure class only, never the
/// address, so userinfo or a sensitive host name cannot leak through them.
fn check_plaintext_policy(addr: &url::Url, allow_plaintext: bool) -> Result<(), String> {
    if addr.scheme() != "http" || host_is_loopback(addr) {
        return Ok(());
    }
    if !allow_plaintext {
        return Err(format!(
            "VAULT_ADDR must use https for a non-loopback Vault host: plaintext http would \
             send VAULT_TOKEN and every fetched secret unencrypted. Use https, or set \
             {ALLOW_PLAINTEXT_ENV}=true to accept plaintext Vault traffic"
        ));
    }
    note_plaintext_opt_in();
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

/// Whether a Vault redirect may be followed with the token attached.
///
/// reqwest strips `Authorization` and `Cookie` on a cross-origin redirect but
/// not `X-Vault-Token`, so the plaintext rule has to hold for every hop, not
/// just `VAULT_ADDR`. An `https` target is always fine. A plaintext target is
/// fine with the opt-in, or when both the address and the target are loopback
/// `http` (a client that may use a proxy never sends plaintext to one).
fn redirect_permitted(target: &url::Url, from_loopback_http: bool, allow_plaintext: bool) -> bool {
    match target.scheme() {
        "https" => true,
        "http" => allow_plaintext || (from_loopback_http && host_is_loopback(target)),
        _ => false,
    }
}

/// The plaintext opt-in warning: not yet needed, recorded before a logging
/// subscriber existed, or emitted.
const PLAINTEXT_WARNING_NONE: u8 = 0;
const PLAINTEXT_WARNING_PENDING: u8 = 1;
const PLAINTEXT_WARNING_EMITTED: u8 = 2;
static PLAINTEXT_WARNING: AtomicU8 = AtomicU8::new(PLAINTEXT_WARNING_NONE);

/// Warn once that the opt-in admitted a plaintext address. Startup secret
/// resolution runs before logging is initialized, so the warning is held until
/// [`emit_deferred_plaintext_warning`] runs rather than dropped.
fn note_plaintext_opt_in() {
    if tracing::dispatcher::has_been_set() {
        if PLAINTEXT_WARNING.swap(PLAINTEXT_WARNING_EMITTED, Ordering::AcqRel)
            != PLAINTEXT_WARNING_EMITTED
        {
            warn_plaintext_opt_in();
        }
    } else {
        let _ = PLAINTEXT_WARNING.compare_exchange(
            PLAINTEXT_WARNING_NONE,
            PLAINTEXT_WARNING_PENDING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

/// Emit the plaintext opt-in warning recorded before logging started.
pub(crate) fn emit_deferred_plaintext_warning() {
    if PLAINTEXT_WARNING
        .compare_exchange(
            PLAINTEXT_WARNING_PENDING,
            PLAINTEXT_WARNING_EMITTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
    {
        warn_plaintext_opt_in();
    }
}

fn warn_plaintext_opt_in() {
    tracing::warn!(
        "VAULT_ADDR uses plaintext http to a non-loopback host because \
         {ALLOW_PLAINTEXT_ENV}=true; VAULT_TOKEN and fetched secrets cross the network \
         unencrypted"
    );
}

/// Build the Vault HTTP transport with the plaintext policy applied past the
/// first hop.
///
/// This mirrors `vaultrs::client::VaultClient::new` (vaultrs 0.8, rustls
/// backend) setting for setting: timeout, certificate verification, CA bundle
/// (only for `https`), client identity, and explicit proxy. It adds the two
/// things vaultrs leaves at reqwest's defaults:
///
/// - a redirect policy that applies [`redirect_permitted`] to every hop;
/// - no proxy for a loopback `http` address, because reqwest honours
///   `HTTP_PROXY` and would otherwise carry a loopback request, token
///   included, to a remote proxy in plaintext.
fn vault_transport(
    settings: &vaultrs::client::VaultClientSettings,
    allow_plaintext: bool,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::ClientBuilder::new().tls_backend_rustls();
    if let Some(timeout) = settings.timeout {
        builder = builder.timeout(timeout);
    }
    builder = builder.tls_danger_accept_invalid_certs(!settings.verify);
    if settings.address.scheme() == "http" {
        builder = builder.tls_certs_only(Vec::new());
    } else {
        for path in &settings.ca_certs {
            let pem = std::fs::read(path)
                .map_err(|e| format!("Failed to read the Vault CA certificate bundle: {e}"))?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|e| format!("Failed to parse the Vault CA certificate bundle: {e}"))?;
            builder = builder.tls_certs_merge(certs);
        }
    }
    if let Some(identity) = &settings.identity {
        builder = builder.identity(identity.clone());
    }
    let loopback_http = settings.address.scheme() == "http" && host_is_loopback(&settings.address);
    if let Some(proxy) = &settings.proxy {
        builder = builder.proxy(
            reqwest::Proxy::all(proxy.as_str())
                .map_err(|e| format!("Failed to configure the Vault proxy: {e}"))?,
        );
    } else if loopback_http {
        builder = builder.no_proxy();
    }
    builder = builder.redirect(reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_VAULT_REDIRECTS {
            return attempt.error("too many Vault redirects");
        }
        if redirect_permitted(attempt.url(), loopback_http, allow_plaintext) {
            attempt.follow()
        } else {
            attempt.error(
                "refused a Vault redirect to a plaintext http address that would carry \
                 VAULT_TOKEN unencrypted",
            )
        }
    }));
    builder
        .build()
        .map_err(|e| format!("Failed to create Vault client: {e}"))
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
        let allow_plaintext = parse_allow_plaintext(env::var(ALLOW_PLAINTEXT_ENV).ok().as_deref())?;
        check_plaintext_policy(&parsed_addr, allow_plaintext)?;

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

        let mut client = vaultrs::client::VaultClient::new(settings)
            .map_err(|e| format!("Failed to create Vault client: {}", e))?;
        // Replace the transport vaultrs built with one that carries the
        // plaintext policy past the first hop. Endpoint middleware (token,
        // API version, namespace) and the base address are untouched.
        client.http.http = vault_transport(&client.settings, allow_plaintext)?;

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
