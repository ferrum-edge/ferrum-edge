//! HashiCorp Vault secret resolution (requires `secrets-vault` feature).

use std::env;
use std::sync::atomic::{AtomicU8, Ordering};

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
        "Vault traffic uses plaintext http to a non-loopback host because \
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
    ca_certs: Vec<reqwest::Certificate>,
    allow_plaintext: bool,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::ClientBuilder::new().tls_backend_rustls();
    if let Some(timeout) = settings.timeout {
        builder = builder.timeout(timeout);
    }
    builder = builder.tls_danger_accept_invalid_certs(!settings.verify);
    if settings.address.scheme() == "http" {
        builder = builder.tls_certs_only(Vec::new());
    } else if !ca_certs.is_empty() {
        builder = builder.tls_certs_merge(ca_certs);
    }
    if let Some(identity) = &settings.identity {
        builder = builder.identity(identity.clone());
    }
    // `localhost` is admitted as loopback by name, so pin it to the loopback
    // addresses rather than trusting the system resolver: NSS or DNS fallback
    // without a hosts entry could otherwise map it to a network address and
    // carry the token there in plaintext. This applies to redirect targets as
    // well, since they go through this same client.
    builder = builder.resolve_to_addrs(
        "localhost",
        &[
            std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
            std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0)),
        ],
    );
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
        // `previous()` includes the original request, so `>` (reqwest's own
        // test) allows exactly `MAX_VAULT_REDIRECTS` hops.
        if attempt.previous().len() > MAX_VAULT_REDIRECTS {
            return attempt.error("too many Vault redirects");
        }
        if redirect_permitted(attempt.url(), loopback_http, allow_plaintext) {
            // A hop the opt-in alone admits carries the token in plaintext off
            // the host, so it gets the same once-per-process warning as a
            // plaintext `VAULT_ADDR`.
            if attempt.url().scheme() == "http" && !host_is_loopback(attempt.url()) {
                note_plaintext_opt_in();
            }
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

/// Diagnostic label for this provider's `FERRUM_TLS_CA_BUNDLE_PATH` reads.
const VAULT_CA_BUNDLE_LABEL: &str = "Vault TLS";

/// Extra trust roots for an `https` Vault transport from
/// `FERRUM_TLS_CA_BUNDLE_PATH`, merged with the platform roots.
///
/// Unset or empty: none. A plaintext `http` address uses no TLS, so the bundle
/// is not read at all. Otherwise it is read through the shared detached,
/// non-blocking, regular-file, size-capped reader, so a FIFO or a stalled
/// mount cannot block the startup secret-resolution runtime, and a bundle that
/// is not PEM or carries no certificate fails closed. Errors name the variable
/// and the failure class, never the path or the bytes.
async fn vault_ca_certs(address: &url::Url) -> Result<Vec<reqwest::Certificate>, String> {
    use super::ca_bundle::CA_BUNDLE_PATH_ENV;

    if address.scheme() == "http" {
        return Ok(Vec::new());
    }
    let Some(path) = env::var_os(CA_BUNDLE_PATH_ENV).filter(|path| !path.is_empty()) else {
        return Ok(Vec::new());
    };
    let pem = super::ca_bundle::read_ca_bundle_detached(path, VAULT_CA_BUNDLE_LABEL).await?;
    let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|_| {
        format!("{CA_BUNDLE_PATH_ENV} is not a valid PEM CA bundle ({VAULT_CA_BUNDLE_LABEL})")
    })?;
    if certs.is_empty() {
        return Err(format!(
            "{CA_BUNDLE_PATH_ENV} contains no certificates ({VAULT_CA_BUNDLE_LABEL})"
        ));
    }
    Ok(certs)
}

/// Reusable Vault client for batch secret resolution.
/// Created once and shared across multiple Vault secret fetches.
pub struct VaultClientWrapper {
    client: vaultrs::client::VaultClient,
}

impl VaultClientWrapper {
    /// Create a new Vault client from standard env vars (`VAULT_ADDR`, `VAULT_TOKEN`).
    ///
    /// Async because `FERRUM_TLS_CA_BUNDLE_PATH` is read through the shared
    /// detached, non-blocking, size-capped reader; callers bound it with the
    /// secret fetch timeout.
    pub async fn new() -> Result<Self, String> {
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

        // vaultrs must never read a file or an ambient TLS default itself.
        // Its `VaultClient::new` reads every `ca_certs` path with a blocking
        // `std::fs::read`, and the builder's unset fields default to ambient
        // variables: `VAULT_CACERT` / `VAULT_CAPATH` (CA paths),
        // `VAULT_CLIENT_CERT` / `VAULT_CLIENT_KEY` (read with a blocking
        // `std::fs::read` inside `build()`, before any timeout can fire), and
        // `VAULT_SKIP_VERIFY` (silently disables verification). Ferrum's Vault
        // TLS inputs are its own: `FERRUM_TLS_CA_BUNDLE_PATH` is the one trust
        // input, read below through the hardened shared reader and installed
        // on the replacement transport; verification is always on; no ambient
        // client identity is loaded.
        settings_builder
            .ca_certs(Vec::new())
            .identity(None)
            .verify(true);

        let settings = settings_builder
            .build()
            .map_err(|e| format!("Failed to build Vault client settings: {}", e))?;

        let ca_certs = vault_ca_certs(&settings.address).await?;
        // `VaultClient::new` is used only for its endpoint middleware (token,
        // API version, namespace): its own reqwest client is replaced below.
        // For an `https` address that throwaway client would initialize the
        // platform verifier with no extra roots, which fails on a host without
        // system CA certificates even when `FERRUM_TLS_CA_BUNDLE_PATH` supplies
        // the only trust anchor. Build it over a plaintext-scheme copy of the
        // address instead (vaultrs then installs an empty `tls_certs_only`
        // store and loads no roots), and restore the real settings and base URL
        // before installing the Ferrum transport. No request is ever sent
        // through the throwaway client.
        let mut construction_settings = settings.clone();
        if construction_settings.address.scheme() == "https" {
            construction_settings
                .address
                .set_scheme("http")
                .map_err(|_| "Failed to create Vault client".to_string())?;
        }
        let mut client = vaultrs::client::VaultClient::new(construction_settings)
            .map_err(|e| format!("Failed to create Vault client: {}", e))?;
        client.http.base = settings.address.as_str().to_string();
        client.settings = settings;
        // Replace the transport vaultrs built with one that carries the
        // plaintext policy past the first hop and trusts the configured bundle.
        client.http.http = vault_transport(&client.settings, ca_certs, allow_plaintext)?;

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
    let wrapper = VaultClientWrapper::new().await?;
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
