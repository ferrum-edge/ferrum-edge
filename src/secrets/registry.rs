//! Registry-backed secret resolution for env and external secret backends.
//!
//! The registry keeps backend-specific client/init logic inside each provider
//! module while centralizing suffix matching, conflict detection, and startup
//! ordering in one place.

use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Duration;
use tracing::info;

#[cfg(feature = "secrets-aws")]
use super::aws;
#[cfg(feature = "secrets-azure")]
use super::azure;
#[cfg(feature = "secrets-gcp")]
use super::gcp;
#[cfg(feature = "secrets-vault")]
use super::vault;
use super::{env, file};

/// Only scan environment variables with this prefix.
const FERRUM_PREFIX: &str = "FERRUM_";

const NON_SECRET_FILE_SUFFIX_KEYS: &[&str] = &["FERRUM_DNS_RESOLVER_HOSTS_FILE"];

/// Substituted for a secret's source reference in an operator-facing error.
const REDACTED_REFERENCE: &str = "<redacted source reference>";

/// Strip a secret's source reference out of a backend error before it reaches
/// an operator.
///
/// A source reference — a file path, a Vault path, an ARN, a Key Vault URL — is
/// treated as sensitive alongside the value it points at: `run` logs this text
/// and `validate` prints it, while the success report deliberately reports the
/// base key and provider name only. Ferrum's own leaf errors no longer
/// interpolate the reference, but provider SDK errors are outside our control
/// and routinely echo the resource they were asked for, so the reference is
/// removed here as well. This is the single boundary every startup fetch passes
/// through, so a new backend cannot bypass it.
///
/// The full reference, its pre-`#` path half, and every provider-normalized
/// component the fetch was actually issued with are replaced, longest first, so
/// a `path#field` reference cannot leak its path and a rewritten reference
/// cannot leak through the rewrite. When a one- or two-character candidate is
/// present in the backend detail, selective replacement would corrupt unrelated
/// text, so the whole provider-controlled detail is replaced with a fixed
/// key-level diagnostic instead.
fn redact_source_reference(error: String, reference: &str, key: &str) -> String {
    const MIN_REDACTABLE_REFERENCE_LEN: usize = 3;

    let mut candidates = source_reference_candidates(reference);
    candidates.sort_unstable();
    candidates.dedup();
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.len()));

    // A one- or two-byte reference cannot be removed selectively: replacing
    // every matching character/pair would destroy the diagnostic, while
    // leaving it alone lets an SDK echo the source reference verbatim. Fail
    // closed to a fixed key-level message whenever such a candidate occurs in
    // the backend detail. The base key is trusted configuration metadata and
    // remains actionable; no text derived from the provider error survives.
    if candidates.iter().any(|candidate| {
        !candidate.is_empty()
            && candidate.len() < MIN_REDACTABLE_REFERENCE_LEN
            && error.contains(candidate)
    }) {
        return format!(
            "Failed to resolve external secret for {key}: provider error withheld to protect the source reference"
        );
    }

    // Single left-to-right pass over the *original* error. A `replace()` loop
    // over the running message re-scans text it just inserted: a reference
    // like `source#field` yields candidates `source#field` and `source`, so
    // after the full reference becomes `<redacted source reference>` the
    // later `source` pass mangles that placeholder. Matching the original
    // keeps substitution single-pass and idempotent — the same rule
    // resolved-value redaction uses — and the placeholder skip below covers a
    // second call (or an error that already carried one).
    let mut out = String::with_capacity(error.len());
    let mut cursor = 0usize;
    while cursor < error.len() {
        let rest = &error[cursor..];

        if rest.starts_with(REDACTED_REFERENCE)
            && !candidates.iter().any(|candidate| {
                candidate.len() >= REDACTED_REFERENCE.len() && rest.starts_with(candidate.as_str())
            })
        {
            out.push_str(REDACTED_REFERENCE);
            cursor += REDACTED_REFERENCE.len();
            continue;
        }

        if let Some(matched) = candidates.iter().find(|candidate| {
            candidate.len() >= MIN_REDACTABLE_REFERENCE_LEN && rest.starts_with(candidate.as_str())
        }) {
            out.push_str(REDACTED_REFERENCE);
            cursor += matched.len();
            continue;
        }

        match rest.chars().next() {
            Some(next) => {
                out.push(next);
                cursor += next.len_utf8();
            }
            None => break,
        }
    }
    out
}

/// Every string form of a source reference that a backend error can plausibly
/// echo.
///
/// The original reference is not always what the provider was asked for. Azure
/// is the case that forces this: `parse_keyvault_reference` splits a Key Vault
/// URL into `(vault_url, secret_name, version)` and the SDK request is built
/// from those components. An SDK error may echo the vault URL, the secret
/// name, the unversioned `/secrets/<name>` path, or the versioned path — none
/// of which necessarily equal the operator's original string (which may also
/// carry a `#` suffix or a TLS `?version=` option). Adding the parsed
/// components — and their recombined unversioned/versioned
/// `<vault_url>/secrets/<secret_name>[/<version>]` forms, so the longest-first
/// pass replaces each as one span — closes that without relying on the
/// operator spelling alone.
///
/// Parsing is attempted on every reference and simply yields nothing for the
/// other providers: a Vault path, a GCP resource name, and an ARN are all
/// rejected by URL-with-host parsing, so no spurious candidate is produced.
fn source_reference_candidates(reference: &str) -> Vec<String> {
    let mut candidates = vec![reference.to_string()];
    if let Some((path, _field)) = reference.split_once('#') {
        candidates.push(path.to_string());
    }

    #[cfg(feature = "secrets-azure")]
    {
        // The `key` argument only shapes the parse error, which is discarded.
        // Both the reference and its pre-`#` half are parsed, because the Key
        // Vault reference an operator writes may carry a `#` suffix that the
        // URL parser would otherwise fold into the fragment.
        let bases: Vec<String> = candidates.clone();
        for base in bases {
            if let Ok((vault_url, secret_name, version)) =
                azure::parse_keyvault_reference(&base, "")
            {
                candidates.push(format!("{vault_url}/secrets/{secret_name}"));
                if let Some(version) = version {
                    candidates.push(format!("{vault_url}/secrets/{secret_name}/{version}"));
                    candidates.push(version);
                }
                candidates.push(vault_url);
                candidates.push(secret_name);
            }
        }
    }

    candidates
}

/// Default timeout (seconds) for individual secret fetch operations from cloud backends.
const DEFAULT_SECRET_FETCH_TIMEOUT_SECS: u64 = 30;

/// Read the secret fetch timeout for the *runtime* single-key paths
/// ([`resolve_secret`], [`resolve_external_reference`]), which run long after
/// settings are loaded and where the conf file is a legitimate source.
fn secret_fetch_timeout() -> Duration {
    parse_fetch_timeout(crate::config::conf_file::resolve_ferrum_var(
        "FERRUM_SECRET_FETCH_TIMEOUT_SECONDS",
    ))
}

/// Read the secret fetch timeout for startup resolution, from the process
/// environment **only**.
///
/// Startup resolution runs before `ferrum.conf` is read, and must keep it that
/// way. The conf-file-aware resolver initializes the process-wide
/// `CONF_FILE_CACHE` on first miss, and that cache is populated from whatever
/// `FERRUM_CONF_PATH` says *at that moment*. Consulting it here would prime the
/// cache from the default/discovered settings file before
/// [`resolve_all_env_secrets`] has had a chance to materialize
/// `FERRUM_CONF_PATH_FILE` into `FERRUM_CONF_PATH` — so an operator who sources
/// the settings path itself from an external secret would have the resolved
/// path installed into an already-populated cache and silently ignored by
/// `validate` and by the gateway for the rest of the process.
///
/// The documented `env > conf file` precedence is therefore deliberately narrowed
/// for this one variable at this one stage: to change the startup fetch timeout,
/// set `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS` in the environment. A `ferrum.conf`
/// value still applies to the runtime single-key fetches above. See
/// `docs/configuration.md`.
fn startup_secret_fetch_timeout() -> Duration {
    parse_fetch_timeout(std::env::var("FERRUM_SECRET_FETCH_TIMEOUT_SECONDS").ok())
}

fn parse_fetch_timeout(raw: Option<String>) -> Duration {
    let secs = raw
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SECRET_FETCH_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// A successfully resolved secret value with its source for logging.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ResolvedSecret {
    pub value: String,
    /// Human-readable source description (e.g. "env", "file:/run/secrets/jwt").
    /// Never contains the secret value itself.
    pub source: String,
    /// Provider version actually returned/fetched when the backend reports one
    /// (for example an Azure Key Vault secret version). Not a configured label.
    pub version: Option<String>,
}

/// The result of resolving all env-based secrets at startup.
///
/// Every vector is sorted by base key. Candidate sources are discovered by
/// iterating `std::env::vars_os()` into a `HashMap`, whose order varies between
/// processes, so an unsorted result would let two runs of `ferrum-edge
/// validate` on identical input print the `Loaded <KEY> from <provider>` lines
/// in different orders. Base keys are unique across the result (two sources for
/// one base key is a conflict error), so ordering by base key is total and
/// stable. See [`resolve_all_env_secrets`].
pub struct ResolvedEnvSecrets {
    /// Resolved `(base_key, value)` pairs to inject into the environment.
    /// Sorted by base key.
    pub vars: Vec<(String, String)>,
    /// Suffixed source keys (e.g., `FERRUM_X_FILE`) to remove from the
    /// environment. Sorted lexicographically, which is base-key order because a
    /// suffixed key is its base key plus a fixed provider suffix.
    pub source_keys_to_remove: Vec<String>,
    /// `(base_key, backend display name)` pairs to report once tracing is
    /// initialized. Sorted by base key.
    pub loaded_sources: Vec<(String, &'static str)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum BackendKind {
    // Used by the intentionally retained single-key `resolve_secret` path,
    // which is not referenced by the production binary in every target.
    #[allow(dead_code)]
    DirectEnv,
    File,
    #[cfg(feature = "secrets-vault")]
    Vault,
    #[cfg(feature = "secrets-aws")]
    Aws,
    #[cfg(feature = "secrets-gcp")]
    Gcp,
    #[cfg(feature = "secrets-azure")]
    Azure,
}

#[derive(Clone)]
pub(crate) struct PendingSecret {
    base_key: String,
    reference: String,
    suffixed_key: String,
    backend_kind: BackendKind,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedPendingSecret {
    base_key: String,
    value: String,
    suffixed_key: String,
}

#[async_trait]
pub(crate) trait SecretBackend: Sync + Send {
    fn kind(&self) -> BackendKind;
    fn name(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn suffix(&self) -> Option<&'static str> {
        None
    }
    #[allow(dead_code)]
    fn resolve_ref(&self, key: &str) -> Option<String>;
    #[allow(dead_code)]
    fn source(&self, reference: &str) -> String;
    fn log_loaded(&self) -> bool {
        self.name() != "environment"
    }

    fn matches_suffix<'a>(&self, raw_key: &'a str) -> Option<&'a str> {
        self.suffix()
            .and_then(|suffix| raw_key.strip_suffix(suffix))
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String>;

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        // Apply the same timeout envelope to every backend, including file
        // reads, so startup cannot hang indefinitely on a blocked mount/FIFO.
        let mut resolved = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let value = tokio::time::timeout(
                timeout,
                self.resolve_one(&secret.reference, &secret.base_key),
            )
            .await
            .map_err(|_| {
                format!(
                    "Timeout resolving {} from {} after {}s",
                    secret.base_key,
                    self.display_name(),
                    timeout.as_secs()
                )
            })?
            .map_err(|error| redact_source_reference(error, &secret.reference, &secret.base_key))?;
            resolved.push(ResolvedPendingSecret {
                base_key: secret.base_key.clone(),
                value,
                suffixed_key: secret.suffixed_key.clone(),
            });
        }
        Ok(resolved)
    }
}

#[allow(dead_code)]
struct DirectEnvBackend;
struct FileBackend;

#[cfg(feature = "secrets-vault")]
struct VaultBackend;
#[cfg(feature = "secrets-aws")]
struct AwsBackend;
#[cfg(feature = "secrets-gcp")]
struct GcpBackend;
#[cfg(feature = "secrets-azure")]
struct AzureBackend;

#[allow(dead_code)]
static DIRECT_ENV_BACKEND: DirectEnvBackend = DirectEnvBackend;
static FILE_BACKEND: FileBackend = FileBackend;
#[cfg(feature = "secrets-vault")]
static VAULT_BACKEND: VaultBackend = VaultBackend;
#[cfg(feature = "secrets-aws")]
static AWS_BACKEND: AwsBackend = AwsBackend;
#[cfg(feature = "secrets-gcp")]
static GCP_BACKEND: GcpBackend = GcpBackend;
#[cfg(feature = "secrets-azure")]
static AZURE_BACKEND: AzureBackend = AzureBackend;

#[allow(dead_code)]
fn all_backends() -> Vec<&'static dyn SecretBackend> {
    #[allow(unused_mut)]
    let mut backends: Vec<&'static dyn SecretBackend> = vec![&DIRECT_ENV_BACKEND, &FILE_BACKEND];
    #[cfg(feature = "secrets-vault")]
    backends.push(&VAULT_BACKEND);
    #[cfg(feature = "secrets-aws")]
    backends.push(&AWS_BACKEND);
    #[cfg(feature = "secrets-gcp")]
    backends.push(&GCP_BACKEND);
    #[cfg(feature = "secrets-azure")]
    backends.push(&AZURE_BACKEND);
    backends
}

fn startup_backends() -> Vec<&'static dyn SecretBackend> {
    #[allow(unused_mut)]
    let mut backends: Vec<&'static dyn SecretBackend> = vec![&FILE_BACKEND];
    #[cfg(feature = "secrets-vault")]
    backends.push(&VAULT_BACKEND);
    #[cfg(feature = "secrets-aws")]
    backends.push(&AWS_BACKEND);
    #[cfg(feature = "secrets-gcp")]
    backends.push(&GCP_BACKEND);
    #[cfg(feature = "secrets-azure")]
    backends.push(&AZURE_BACKEND);
    backends
}

fn suffix_backends() -> Vec<&'static dyn SecretBackend> {
    #[allow(unused_mut)]
    let mut backends: Vec<&'static dyn SecretBackend> = vec![&FILE_BACKEND];
    #[cfg(feature = "secrets-azure")]
    backends.insert(0, &AZURE_BACKEND);
    #[cfg(feature = "secrets-vault")]
    backends.insert(
        #[cfg(feature = "secrets-azure")]
        1,
        #[cfg(not(feature = "secrets-azure"))]
        0,
        &VAULT_BACKEND,
    );
    #[cfg(feature = "secrets-aws")]
    backends.push(&AWS_BACKEND);
    #[cfg(feature = "secrets-gcp")]
    backends.push(&GCP_BACKEND);
    backends
}

#[allow(dead_code)]
fn timeout_error(key: &str, backend_name: &str, timeout: Duration) -> String {
    format!(
        "Timeout resolving {} from {} after {}s",
        key,
        backend_name,
        timeout.as_secs()
    )
}

/// Timeout while constructing a cloud provider client before any secret fetch.
///
/// Deterministic and reference-free: client/credential discovery can stall on
/// ADC or instance-metadata without ever touching a source reference, so the
/// message names only the backend and the configured bound.
#[cfg(any(feature = "secrets-aws", feature = "secrets-gcp"))]
fn client_init_timeout_error(backend_name: &str, timeout: Duration) -> String {
    format!(
        "Timeout initializing {} client after {}s",
        backend_name,
        timeout.as_secs()
    )
}

#[cfg(any(
    feature = "secrets-vault",
    feature = "secrets-aws",
    feature = "secrets-gcp",
    feature = "secrets-azure"
))]
async fn resolve_many_concurrent<C, F>(
    secrets: &[PendingSecret],
    timeout: Duration,
    backend_name: &'static str,
    client: &C,
    fetch: F,
) -> Result<Vec<ResolvedPendingSecret>, String>
where
    C: Sync,
    F: for<'a> Fn(
        &'a C,
        &'a str,
        &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<String, String>>,
{
    let futs: Vec<_> = secrets
        .iter()
        .map(|secret| async {
            let value =
                tokio::time::timeout(timeout, fetch(client, &secret.reference, &secret.base_key))
                    .await
                    .map_err(|_| timeout_error(&secret.base_key, backend_name, timeout))?
                    .map_err(|error| {
                        redact_source_reference(error, &secret.reference, &secret.base_key)
                    })?;
            Ok::<_, String>(ResolvedPendingSecret {
                base_key: secret.base_key.clone(),
                value,
                suffixed_key: secret.suffixed_key.clone(),
            })
        })
        .collect();

    let mut resolved = Vec::with_capacity(secrets.len());
    for item in futures_util::future::join_all(futs).await {
        resolved.push(item?);
    }
    Ok(resolved)
}

fn match_suffix(raw_key: &str) -> Option<(&'static dyn SecretBackend, &str)> {
    if NON_SECRET_FILE_SUFFIX_KEYS.contains(&raw_key) {
        return None;
    }
    for backend in suffix_backends() {
        if let Some(base) = backend.matches_suffix(raw_key) {
            return Some((backend, base));
        }
    }
    None
}

fn unsupported_cloud_suffix(raw_key: &str) -> Option<(&'static str, &'static str)> {
    const KNOWN: [(&str, &str, bool); 4] = [
        ("_AZURE", "Azure Key Vault", cfg!(feature = "secrets-azure")),
        ("_VAULT", "Vault", cfg!(feature = "secrets-vault")),
        ("_AWS", "AWS Secrets Manager", cfg!(feature = "secrets-aws")),
        ("_GCP", "GCP Secret Manager", cfg!(feature = "secrets-gcp")),
    ];

    for (suffix, backend_name, enabled) in KNOWN {
        if raw_key.ends_with(suffix) && !enabled {
            return Some((suffix, backend_name));
        }
    }

    None
}

/// Every suffix that names an external secret source for a base `FERRUM_*`
/// variable, including providers this build may not have compiled in.
///
/// Deliberately not feature-gated. An unsupported suffix is a *fail-closed
/// error* from [`resolve_all_env_secrets`], not an ignored variable, so callers
/// asking "is this key sourced externally?" must answer the same way in every
/// build — otherwise a binary without, say, `secrets-vault` would treat
/// `FERRUM_CONF_PATH_VAULT` as absent and quietly take a different code path
/// before the error is ever raised.
pub const EXTERNAL_SECRET_SUFFIXES: [&str; 5] = ["_FILE", "_VAULT", "_AWS", "_AZURE", "_GCP"];

/// True when `base_key`'s value is configured to come from an external secret
/// source rather than from the environment directly.
///
/// Uses the same "non-empty means set" rule as discovery in
/// [`resolve_all_env_secrets`], so the two cannot disagree about whether a
/// source exists.
pub fn external_source_configured(base_key: &str) -> bool {
    EXTERNAL_SECRET_SUFFIXES.iter().any(|suffix| {
        let suffixed_key = format!("{base_key}{suffix}");
        if NON_SECRET_FILE_SUFFIX_KEYS.contains(&suffixed_key.as_str()) {
            return false;
        }
        env_var_os_is_set(&suffixed_key)
    })
}

/// Render a non-Unicode environment variable name for an operator diagnostic
/// without disclosing its bytes.
///
/// Every byte that is not an ASCII alphanumeric or `_` — which is every byte a
/// legal `FERRUM_*` name can contain — becomes `?`. That keeps the ASCII skeleton
/// an operator needs to find the variable while emitting nothing that could
/// reconstruct undecodable content, and it is deterministic, so two runs on the
/// same environment produce the same message.
fn sanitize_env_key(key: &std::ffi::OsStr) -> String {
    key.as_encoded_bytes()
        .iter()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || *byte == b'_' {
                *byte as char
            } else {
                '?'
            }
        })
        .collect()
}

/// True when a variable is set to a non-empty value, tolerating a value that is
/// not valid Unicode.
///
/// `std::env::var` reports a non-Unicode value as `Err`, which would read as
/// *unset* here. That matters only for conflict detection, but there it is
/// load-bearing: a base key holding undecodable bytes is still a directly
/// configured source, and treating it as absent would let a suffixed source
/// resolve alongside it and silently overwrite it instead of failing the
/// documented "only one source is allowed" check.
fn env_var_os_is_set(key: &str) -> bool {
    std::env::var_os(key).is_some_and(|value| !value.is_empty())
}

fn unsupported_cloud_suffix_for_base_key(key: &str) -> Option<(&'static str, &'static str)> {
    for suffix in ["_AZURE", "_VAULT", "_AWS", "_GCP"] {
        let suffixed_key = format!("{key}{suffix}");
        let is_set = env_var_os_is_set(&suffixed_key);
        if is_set && let Some(unsupported) = unsupported_cloud_suffix(&suffixed_key) {
            return Some(unsupported);
        }
    }
    None
}

pub async fn resolve_all_env_secrets() -> Result<ResolvedEnvSecrets, String> {
    let mut to_resolve: HashMap<String, Vec<(String, String, BackendKind)>> = HashMap::new();
    // Collected rather than returned on first sight: `std::env::vars_os()` order
    // varies between processes, so returning inside the loop would let two
    // runs on an identical environment blame a different `FERRUM_*_AWS`/`_GCP`
    // key. Sorted and reported after discovery, matching the determinism the
    // rest of `ResolvedEnvSecrets` already guarantees.
    let mut unsupported: Vec<(String, &'static str, &'static str)> = Vec::new();

    // Same collect-then-report reasoning as `unsupported`, for the same
    // determinism reason.
    let mut invalid_unicode: Vec<String> = Vec::new();

    // Non-Unicode values on ordinary `FERRUM_*` variables — i.e. direct
    // configuration rather than a secret *source reference*. Kept separate from
    // `invalid_unicode` because it is reported later, after the conflict check;
    // see the report site below for why the ordering is load-bearing.
    let mut invalid_unicode_direct: Vec<String> = Vec::new();

    // `std::env::vars()` *panics* on any variable whose name or value is not
    // valid Unicode, and it panics during iteration — before this loop can
    // filter to `FERRUM_*`. A single unrelated non-UTF-8 variable elsewhere in
    // a POSIX environment would therefore abort `run` and `validate` outright,
    // with no diagnostic. `vars_os` yields the same entries without decoding,
    // so an unrelated variable is skipped by the prefix screen below and never
    // decoded at all.
    for (raw_key_os, value_os) in std::env::vars_os() {
        // Screened on raw bytes so a non-Unicode name is rejected here rather
        // than decoded. `FERRUM_` is ASCII, and `as_encoded_bytes` guarantees
        // ASCII substrings match at the same positions they would in the
        // decoded string, so this cannot match mid-character.
        if !raw_key_os
            .as_encoded_bytes()
            .starts_with(FERRUM_PREFIX.as_bytes())
        {
            continue;
        }
        let Some(raw_key) = raw_key_os.to_str() else {
            // A `FERRUM_*` name we cannot decode may well be a suffixed source
            // (the suffix is at the *end*, which we cannot read). Skipping it
            // would silently drop a configured secret source, so fail closed.
            invalid_unicode.push(sanitize_env_key(&raw_key_os));
            continue;
        };
        let Some(value) = value_os.to_str() else {
            // The name decoded, so we can tell whether this is a *source*
            // reference or an ordinary direct value. Both fail closed, but at
            // different points and with different messages.
            //
            // An undecodable source reference is unusable: we cannot issue the
            // fetch it describes.
            //
            // An undecodable *direct* value is a silent-misconfiguration
            // hazard, which is why it cannot simply be skipped. Every
            // downstream config resolver reads the environment with
            // `std::env::var`, which reports non-Unicode as `Err` — that is,
            // as **unset**. So a `FERRUM_ADMIN_HTTP_PORT` or
            // `FERRUM_CONF_PATH` holding undecodable bytes does not fail; it
            // silently falls through to `ferrum.conf` or to the built-in
            // default, and the gateway comes up on settings the operator never
            // chose. `env_var_os_is_set` makes such a value visible to the
            // conflict check below, but nothing else ever sees it.
            //
            // Every `FERRUM_*` name is in Ferrum's own configuration
            // namespace, and no Ferrum setting is parsed from anything but a
            // `String`, so undecodable bytes can never be a value Ferrum could
            // have used. There is no "definitely unrelated" `FERRUM_*` name to
            // carve out — including the `NON_SECRET_FILE_SUFFIX_KEYS` entries,
            // which are ordinary path settings that merely end in `_FILE`.
            // Unrelated non-Ferrum variables never reach here at all: the raw
            // prefix screen above skipped them without decoding.
            let is_source = unsupported_cloud_suffix(raw_key).is_some()
                || match_suffix(raw_key).is_some_and(|(_, base_key)| !base_key.is_empty());
            if is_source {
                invalid_unicode.push(sanitize_env_key(&raw_key_os));
            } else {
                invalid_unicode_direct.push(sanitize_env_key(&raw_key_os));
            }
            continue;
        };
        // Empty suffixed variables are unset-equivalent for every backend.
        // Check this before feature gating so behavior does not change based
        // on whether a cloud provider was compiled into the binary.
        if value.is_empty() {
            continue;
        }
        if let Some((suffix, backend_name)) = unsupported_cloud_suffix(raw_key) {
            unsupported.push((raw_key.to_string(), suffix, backend_name));
            continue;
        }
        if let Some((backend, base_key)) = match_suffix(raw_key) {
            if base_key.is_empty() {
                continue;
            }
            to_resolve.entry(base_key.to_string()).or_default().push((
                raw_key.to_string(),
                value.to_string(),
                backend.kind(),
            ));
        }
    }

    // Fail closed before anything is fetched, naming the lexicographically
    // first offender so the message is identical across processes. The name is
    // sanitized to its ASCII skeleton: an operator needs to find the variable,
    // and undecodable bytes are never echoed.
    if !invalid_unicode.is_empty() {
        invalid_unicode.sort();
        return Err(format!(
            "Environment variable {} is not valid Unicode. External secret source names and \
             references must be valid Unicode; fix or unset the variable.",
            invalid_unicode[0]
        ));
    }

    // Fail closed on an unsupported suffix before anything is fetched, naming
    // the lexicographically first offending variable so the message is
    // identical across processes with the same environment.
    if !unsupported.is_empty() {
        unsupported.sort_by(|left, right| left.0.cmp(&right.0));
        let (raw_key, suffix, backend_name) = &unsupported[0];
        return Err(format!(
            "Unsupported secret suffix {} on {}: {} support is not enabled in this build.",
            suffix, raw_key, backend_name
        ));
    }

    let mut pending: Vec<PendingSecret> = Vec::new();

    // Iterate base keys in sorted order rather than `HashMap` order. This fixes
    // both which conflict is reported first when several keys are misconfigured
    // and the order of the resolved results, so two runs on identical input
    // produce byte-identical output. See [`ResolvedEnvSecrets`].
    let mut base_keys: Vec<&String> = to_resolve.keys().collect();
    base_keys.sort();

    for base_key in base_keys {
        let sources = &to_resolve[base_key];
        // `var_os`, not `var`: a base key holding non-Unicode bytes is still a
        // directly configured source. Reading it with `var` would report it as
        // unset and let a suffixed source resolve on top of it instead of
        // failing the "only one source is allowed" check below.
        let direct_set = env_var_os_is_set(base_key);

        let total_sources = sources.len() + if direct_set { 1 } else { 0 };
        if total_sources > 1 {
            let mut names: Vec<String> = Vec::new();
            for (suffixed_key, _, _) in sources {
                names.push(suffixed_key.clone());
            }
            // Suffixed sources arrive in `std::env::vars_os()` order; sort them so
            // the conflict message is byte-identical across processes. The
            // direct variable is prepended afterwards because it is the source
            // an operator is most likely to have forgotten about.
            names.sort();
            if direct_set {
                names.insert(0, "direct env var".to_string());
            }
            return Err(format!(
                "Multiple secret sources configured for {}: {}. Only one source is allowed.",
                base_key,
                names.join(", ")
            ));
        }

        let (suffixed_key, reference, backend) = &sources[0];
        pending.push(PendingSecret {
            base_key: base_key.to_string(),
            reference: reference.clone(),
            suffixed_key: suffixed_key.clone(),
            backend_kind: *backend,
        });
    }

    // Reported *after* the conflict check, deliberately. A base key that holds
    // undecodable bytes *and* has a suffixed source is a genuine
    // multiple-sources misconfiguration, and that is the more specific and more
    // actionable diagnostic; `env_var_os_is_set` already counts the undecodable
    // direct value as a source there, so that case is caught above and never
    // reaches here. What is left is the case nothing else catches: a direct
    // Ferrum value that no source competes with, which would otherwise read as
    // unset to every downstream `std::env::var` and be silently replaced by a
    // conf-file entry or a default.
    //
    // Lexicographically first offender, sanitized to its ASCII skeleton, for
    // the same determinism and non-disclosure reasons as the checks above.
    if !invalid_unicode_direct.is_empty() {
        invalid_unicode_direct.sort();
        return Err(format!(
            "Environment variable {} is not valid Unicode. Ferrum configuration values must be \
             valid Unicode; fix or unset the variable.",
            invalid_unicode_direct[0]
        ));
    }

    let fetch_timeout = startup_secret_fetch_timeout();

    let mut results = ResolvedEnvSecrets {
        vars: Vec::new(),
        source_keys_to_remove: Vec::new(),
        loaded_sources: Vec::new(),
    };

    for backend in startup_backends() {
        let backend_pending: Vec<PendingSecret> = pending
            .iter()
            .filter(|s| s.backend_kind == backend.kind())
            .cloned()
            .collect();
        if backend_pending.is_empty() {
            continue;
        }

        let resolved = backend
            .resolve_many(&backend_pending, fetch_timeout)
            .await?;
        for item in resolved {
            // A process environment value cannot contain a NUL byte:
            // `std::env::set_var` panics on one. Startup resolution now runs
            // before any settings are parsed, so a `_FILE` source pointing at a
            // binary blob — or a cloud backend returning one — would abort the
            // process here instead of producing the sanitized resolution error
            // `validate` exists to report. Reject it as an ordinary fetch
            // failure, naming the base key and provider and never the value.
            if item.value.contains('\0') {
                return Err(format!(
                    "Secret resolved for {} from {} contains a NUL byte and cannot be placed in the process environment.",
                    item.base_key,
                    backend.display_name()
                ));
            }
            if backend.log_loaded() {
                results
                    .loaded_sources
                    .push((item.base_key.clone(), backend.display_name()));
            }
            results.vars.push((item.base_key, item.value));
            results.source_keys_to_remove.push(item.suffixed_key);
        }
    }

    // Results are accumulated provider by provider, so they are grouped by
    // backend rather than ordered by base key. Sort them into the documented
    // base-key order: this is what `validate` prints, and an operator diffing
    // two reports must not see spurious reordering.
    results.vars.sort_by(|left, right| left.0.cmp(&right.0));
    results
        .loaded_sources
        .sort_by(|left, right| left.0.cmp(&right.0));
    results.source_keys_to_remove.sort();

    Ok(results)
}

#[allow(dead_code)]
/// Resolve a single secret key across all configured backends.
///
/// Startup uses `resolve_all_env_secrets()` for bulk env injection; this helper
/// remains for the existing single-key tests and ad-hoc secret lookups.
pub async fn resolve_secret(key: &str) -> Result<Option<ResolvedSecret>, String> {
    if let Some((suffix, backend_name)) = unsupported_cloud_suffix_for_base_key(key) {
        return Err(format!(
            "Unsupported secret suffix {suffix} on {key}{suffix}: {backend_name} support is not enabled in this build."
        ));
    }

    let mut sources: Vec<(&'static dyn SecretBackend, String)> = Vec::new();

    for backend in all_backends() {
        if let Some(reference) = backend.resolve_ref(key) {
            sources.push((backend, reference));
        }
    }

    if sources.len() > 1 {
        let names: Vec<&str> = sources.iter().map(|(backend, _)| backend.name()).collect();
        return Err(format!(
            "Multiple secret sources configured for {}: {}. Only one source is allowed.",
            key,
            names.join(", ")
        ));
    }

    let Some((backend, reference)) = sources.into_iter().next() else {
        return Ok(None);
    };

    let value = tokio::time::timeout(secret_fetch_timeout(), backend.resolve_one(&reference, key))
        .await
        .map_err(|_| timeout_error(key, backend.display_name(), secret_fetch_timeout()))?
        .map_err(|error| redact_source_reference(error, &reference, key))?;

    if backend.log_loaded() {
        info!("Loaded {} from {}", key, backend.display_name());
    }

    Ok(Some(ResolvedSecret {
        value,
        source: backend.source(&reference),
        version: None,
    }))
}

/// Resolve a direct provider reference such as a `vault://...` or `aws://...`
/// TLS material URI.
///
/// Unlike [`resolve_secret`], this does not inspect environment variables for
/// suffixed variants; the caller has already selected the provider and passed
/// its backend-specific reference. The same backend clients, timeouts, and
/// feature gates are used so typed TLS source URIs do not duplicate provider
/// setup logic.
pub async fn resolve_external_reference(
    provider: &str,
    reference: &str,
    key: &str,
) -> Result<ResolvedSecret, String> {
    if let Some(display_name) = unsupported_provider_name(provider) {
        return Err(format!(
            "{} support is not enabled in this build",
            display_name
        ));
    }

    let Some(backend) = suffix_backends()
        .into_iter()
        .find(|backend| backend.name() == provider)
    else {
        return Err(format!("Unsupported secret provider scheme '{}'", provider));
    };

    // Azure reports the version actually returned by Key Vault. Take the
    // richer fetch path so TLS inventory / materialization can stamp that
    // version rather than a configured query label that was never sent.
    #[cfg(feature = "secrets-azure")]
    if provider == "azure" {
        let secret =
            tokio::time::timeout(secret_fetch_timeout(), azure::fetch_secret(reference, key))
                .await
                .map_err(|_| timeout_error(key, backend.display_name(), secret_fetch_timeout()))?
                .map_err(|error| redact_source_reference(error, reference, key))?;

        if backend.log_loaded() {
            info!("Loaded {} from {}", key, backend.display_name());
        }

        return Ok(ResolvedSecret {
            value: secret.value,
            source: backend.source(reference),
            version: secret.version,
        });
    }

    let value = tokio::time::timeout(secret_fetch_timeout(), backend.resolve_one(reference, key))
        .await
        .map_err(|_| timeout_error(key, backend.display_name(), secret_fetch_timeout()))?
        .map_err(|error| redact_source_reference(error, reference, key))?;

    if backend.log_loaded() {
        info!("Loaded {} from {}", key, backend.display_name());
    }

    Ok(ResolvedSecret {
        value,
        source: backend.source(reference),
        version: None,
    })
}

fn unsupported_provider_name(provider: &str) -> Option<&'static str> {
    match provider {
        "vault" if !cfg!(feature = "secrets-vault") => Some("Vault"),
        "aws" if !cfg!(feature = "secrets-aws") => Some("AWS Secrets Manager"),
        "gcp" if !cfg!(feature = "secrets-gcp") => Some("GCP Secret Manager"),
        "azure" if !cfg!(feature = "secrets-azure") => Some("Azure Key Vault"),
        _ => None,
    }
}

#[async_trait]
impl SecretBackend for DirectEnvBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::DirectEnv
    }

    fn name(&self) -> &'static str {
        "direct"
    }

    fn display_name(&self) -> &'static str {
        "environment"
    }

    fn log_loaded(&self) -> bool {
        false
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        env::resolve(key)
    }

    fn source(&self, _reference: &str) -> String {
        "env".to_string()
    }

    async fn resolve_one(&self, _reference: &str, key: &str) -> Result<String, String> {
        env::resolve(key).ok_or_else(|| {
            format!(
                "Environment variable {} was not set when resolving direct env secret",
                key
            )
        })
    }
}

#[async_trait]
impl SecretBackend for FileBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::File
    }

    fn name(&self) -> &'static str {
        "file"
    }

    fn display_name(&self) -> &'static str {
        "file"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_FILE")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        file::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("file:{}", reference)
    }

    /// Read the file on a **detached OS thread**, not `spawn_blocking`.
    ///
    /// A `_FILE` source can be a FIFO with no writer or a stalled network
    /// mount, where `open`/`read` blocks indefinitely and is not interruptible.
    /// `tokio::time::timeout` around a `spawn_blocking` join handle returns on
    /// schedule but does not stop the blocking task, and dropping the runtime
    /// waits for its blocking pool to quiesce — so the caller's timeout was
    /// honored and the process then hung anyway, at runtime shutdown. That is
    /// exactly the bad local source `validate` exists to catch, and it made the
    /// new `validate` path unbounded.
    ///
    /// A detached thread is owned by no runtime: the timeout drops the receiver
    /// and returns, the temporary startup runtime drops immediately, and the
    /// process is free to exit — Rust does not join detached threads at exit.
    ///
    /// **Residual, deliberate and bounded:** the abandoned thread stays parked
    /// in the kernel until the read completes or the process exits. Startup
    /// treats a fetch timeout as fatal, so `run`/`validate` leak at most one
    /// thread per configured `_FILE` source in the one run that is about to
    /// exit non-zero. There is no path that leaks per request or in a loop.
    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        let reference = reference.to_string();
        let key = key.to_string();
        let key_for_error = key.clone();

        let (sender, receiver) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("ferrum-secret-file".to_string())
            .spawn(move || {
                // The receiver is gone when the caller timed out; the result is
                // then simply dropped.
                let _ = sender.send(file::read_secret(&reference, &key));
            })
            .map_err(|err| {
                format!(
                    "Failed to start file secret read thread for {}: {}",
                    key_for_error, err
                )
            })?;

        receiver.await.map_err(|_| {
            format!(
                "File secret read for {} ended without producing a result",
                key_for_error
            )
        })?
    }
}

#[cfg(feature = "secrets-vault")]
#[async_trait]
impl SecretBackend for VaultBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Vault
    }

    fn name(&self) -> &'static str {
        "vault"
    }

    fn display_name(&self) -> &'static str {
        "Vault"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_VAULT")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        vault::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("vault:{}", reference)
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        vault::fetch_secret(reference, key).await
    }

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        let client = vault::VaultClientWrapper::new()?;
        resolve_many_concurrent(
            secrets,
            timeout,
            self.display_name(),
            &client,
            |client, reference, key| Box::pin(client.fetch_secret(reference, key)),
        )
        .await
    }
}

#[cfg(feature = "secrets-aws")]
#[async_trait]
impl SecretBackend for AwsBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Aws
    }

    fn name(&self) -> &'static str {
        "aws"
    }

    fn display_name(&self) -> &'static str {
        "AWS Secrets Manager"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_AWS")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        aws::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("aws:{}", reference)
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        aws::fetch_secret(reference, key).await
    }

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        // Credential-chain discovery is async and can stall on instance
        // metadata the same way GCP ADC can; bound it with the same timeout
        // used for each subsequent fetch (one construction, not per secret).
        let client = tokio::time::timeout(timeout, aws::AwsClientWrapper::new())
            .await
            .map_err(|_| client_init_timeout_error(self.display_name(), timeout))?;
        resolve_many_concurrent(
            secrets,
            timeout,
            self.display_name(),
            &client,
            |client, reference, key| Box::pin(client.fetch_secret(reference, key)),
        )
        .await
    }
}

#[cfg(feature = "secrets-gcp")]
#[async_trait]
impl SecretBackend for GcpBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Gcp
    }

    fn name(&self) -> &'static str {
        "gcp"
    }

    fn display_name(&self) -> &'static str {
        "GCP Secret Manager"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_GCP")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        gcp::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("gcp:{}", reference)
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        gcp::fetch_secret(reference, key).await
    }

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        // Startup constructor: the endpoint override is read from the
        // environment only, so building this client cannot prime
        // `CONF_FILE_CACHE` before a `FERRUM_CONF_PATH_FILE` has been
        // materialized. See `gcp::endpoint_override_from_env`.
        //
        // ADC / metadata-service discovery runs *before* per-fetch timeouts
        // in `resolve_many_concurrent`, so bound client construction with the
        // same configured timeout (once per provider batch, not per secret).
        let client = tokio::time::timeout(timeout, gcp::GcpClientWrapper::new_for_startup())
            .await
            .map_err(|_| client_init_timeout_error(self.display_name(), timeout))??;
        resolve_many_concurrent(
            secrets,
            timeout,
            self.display_name(),
            &client,
            |client, reference, key| Box::pin(client.fetch_secret(reference, key)),
        )
        .await
    }
}

#[cfg(feature = "secrets-azure")]
#[async_trait]
impl SecretBackend for AzureBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Azure
    }

    fn name(&self) -> &'static str {
        "azure"
    }

    fn display_name(&self) -> &'static str {
        "Azure Key Vault"
    }

    fn suffix(&self) -> Option<&'static str> {
        Some("_AZURE")
    }

    fn resolve_ref(&self, key: &str) -> Option<String> {
        azure::resolve_ref(key)
    }

    fn source(&self, reference: &str) -> String {
        format!("azure:{}", reference)
    }

    async fn resolve_one(&self, reference: &str, key: &str) -> Result<String, String> {
        Ok(azure::fetch_secret(reference, key).await?.value)
    }

    async fn resolve_many(
        &self,
        secrets: &[PendingSecret],
        timeout: Duration,
    ) -> Result<Vec<ResolvedPendingSecret>, String> {
        let creds = azure::AzureCredentials::new()?;
        resolve_many_concurrent(
            secrets,
            timeout,
            self.display_name(),
            &creds,
            |creds, reference, key| {
                Box::pin(async move { Ok(creds.fetch_secret(reference, key).await?.value) })
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[cfg(any(feature = "secrets-aws", feature = "secrets-gcp"))]
    #[test]
    fn client_init_timeout_error_is_deterministic_and_reference_free() {
        let err =
            client_init_timeout_error("GCP Secret Manager", std::time::Duration::from_secs(7));
        assert_eq!(
            err,
            "Timeout initializing GCP Secret Manager client after 7s"
        );
        assert!(
            !err.contains("projects/")
                && !err.contains("secrets/")
                && !err.contains("://")
                && !err.contains('/'),
            "client-init timeout must not echo source references: {err}"
        );
    }

    #[test]
    fn match_suffix_file() {
        let (backend, base) = match_suffix("FERRUM_DB_URL_FILE").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend.name(), "file");
    }

    #[cfg(feature = "secrets-vault")]
    #[test]
    fn match_suffix_vault() {
        let (backend, base) = match_suffix("FERRUM_JWT_SECRET_VAULT").unwrap();
        assert_eq!(base, "FERRUM_JWT_SECRET");
        assert_eq!(backend.name(), "vault");
    }

    #[cfg(feature = "secrets-aws")]
    #[test]
    fn match_suffix_aws() {
        let (backend, base) = match_suffix("FERRUM_DB_URL_AWS").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend.name(), "aws");
    }

    #[cfg(feature = "secrets-gcp")]
    #[test]
    fn match_suffix_gcp() {
        let (backend, base) = match_suffix("FERRUM_DB_URL_GCP").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend.name(), "gcp");
    }

    #[cfg(feature = "secrets-azure")]
    #[test]
    fn match_suffix_azure() {
        let (backend, base) = match_suffix("FERRUM_DB_URL_AZURE").unwrap();
        assert_eq!(base, "FERRUM_DB_URL");
        assert_eq!(backend.name(), "azure");
    }

    #[test]
    fn match_suffix_no_match() {
        assert!(match_suffix("FERRUM_DB_URL").is_none());
        assert!(match_suffix("FERRUM_DB_URL_ETCD").is_none());
        assert!(match_suffix("FERRUM_DNS_RESOLVER_HOSTS_FILE").is_none());
        assert!(match_suffix("").is_none());
        assert!(match_suffix("RANDOM_KEY").is_none());
    }

    #[test]
    fn match_suffix_bare_suffix_returns_empty_base() {
        let (backend, base) = match_suffix("_FILE").unwrap();
        assert_eq!(base, "");
        assert_eq!(backend.name(), "file");
    }

    #[cfg(feature = "secrets-azure")]
    #[test]
    fn match_suffix_azure_checked_before_file() {
        let (backend, base) = match_suffix("FERRUM_X_AZURE").unwrap();
        assert_eq!(base, "FERRUM_X");
        assert_eq!(backend.name(), "azure");
    }

    #[test]
    fn match_suffix_case_sensitive() {
        assert!(match_suffix("FERRUM_DB_URL_file").is_none());
        assert!(match_suffix("FERRUM_DB_URL_vault").is_none());
        assert!(match_suffix("FERRUM_DB_URL_aws").is_none());
    }

    /// A source reference is not always what the provider was asked for.
    ///
    /// `parse_keyvault_reference` splits a versioned URL into vault/name/version
    /// components. An SDK error may echo the unversioned request path, the
    /// versioned path, or only the vault host / secret name — none of which
    /// equal the operator string alone. Redaction must cover every normalized
    /// component.
    ///
    /// Kept inline because `redact_source_reference` is private and the whole
    /// point of the boundary is that no caller can bypass it; exercising it
    /// externally would mean widening the API it exists to constrain.
    #[cfg(feature = "secrets-azure")]
    #[test]
    fn redact_source_reference_covers_azure_normalized_components() {
        const REFERENCE: &str =
            "https://ferrum-vault-sentinel.vault.azure.net:8443/secrets/jwt-name-sentinel/v9abc";
        // Shaped like an `azure_core` transport error, which may echo either the
        // unversioned or versioned URL plus the secret name.
        let sdk_error = "Failed to get Azure secret for FERRUM_ADMIN_JWT_SECRET: \
             HTTP 404 from https://ferrum-vault-sentinel.vault.azure.net:8443\
             /secrets/jwt-name-sentinel/v9abc?api-version=7.4 (secret 'jwt-name-sentinel' \
             in https://ferrum-vault-sentinel.vault.azure.net:8443)"
            .to_string();

        let redacted = redact_source_reference(sdk_error, REFERENCE, "FERRUM_ADMIN_JWT_SECRET");

        assert!(
            !redacted.contains("ferrum-vault-sentinel")
                && !redacted.contains("jwt-name-sentinel")
                && !redacted.contains("vault.azure.net")
                && !redacted.contains("v9abc"),
            "normalized Azure components must not survive redaction: {redacted}"
        );
        // Base key and failure class stay actionable.
        assert!(
            redacted.contains("FERRUM_ADMIN_JWT_SECRET") && redacted.contains("404"),
            "redaction must keep the actionable parts: {redacted}"
        );
        assert!(
            redacted.contains(REDACTED_REFERENCE),
            "expected the placeholder to be present: {redacted}"
        );
    }

    /// A later, shorter candidate must not re-scan a placeholder an earlier
    /// longer match just inserted.
    ///
    /// `source#field` yields both `source#field` and `source`. A `replace()`
    /// loop over the running message turns the first hit into
    /// `<redacted source reference>` and then the `source` pass mangles that
    /// placeholder. Single-pass matching over the original error keeps the
    /// placeholder intact.
    #[test]
    fn redact_source_reference_does_not_mangle_its_own_placeholder() {
        let error =
            "backend failed for source#field: permission denied (source unavailable)".to_string();
        let redacted = redact_source_reference(error, "source#field", "FERRUM_TEST_SECRET");
        assert!(
            !redacted.contains("source#field"),
            "the full reference must not survive: {redacted}"
        );
        assert_eq!(
            redacted.matches(REDACTED_REFERENCE).count(),
            2,
            "both the full reference and the bare path half must redact once each: {redacted}"
        );
        assert!(
            !redacted.contains(&format!("<redacted {REDACTED_REFERENCE}")),
            "placeholder must not be re-redacted: {redacted}"
        );
        // Idempotent: a second pass leaves the message byte-for-byte identical.
        assert_eq!(
            redact_source_reference(redacted.clone(), "source#field", "FERRUM_TEST_SECRET",),
            redacted
        );
    }

    /// A short provider identifier cannot be selectively replaced without
    /// shredding unrelated words in the SDK error. It is still a source
    /// reference, so the safe fallback is a fixed key-level diagnostic rather
    /// than emitting the provider detail unchanged.
    #[test]
    fn redact_source_reference_fails_closed_for_short_reference() {
        let redacted = redact_source_reference(
            "AWS request for secret x failed with HTTP 404".to_string(),
            "x",
            "FERRUM_ADMIN_JWT_SECRET",
        );

        assert_eq!(
            redacted,
            "Failed to resolve external secret for FERRUM_ADMIN_JWT_SECRET: provider error withheld to protect the source reference"
        );
        assert!(
            !redacted.contains("HTTP 404") && !redacted.contains("AWS request"),
            "no provider-controlled detail may survive the fail-closed path: {redacted}"
        );
    }

    /// Non-Azure references must not gain spurious candidates from the Azure
    /// parse attempt, which would over-redact unrelated diagnostics.
    #[test]
    fn source_reference_candidates_ignores_non_url_references() {
        for reference in [
            "secret/data/ferrum#admin_jwt",
            "projects/p/secrets/s/versions/latest",
            "arn:aws:secretsmanager:us-east-1:1:secret:ferrum",
            "/run/secrets/admin-jwt",
        ] {
            let candidates = source_reference_candidates(reference);
            assert!(
                candidates.len() <= 2,
                "{reference} produced unexpected candidates: {candidates:?}"
            );
            assert!(candidates.contains(&reference.to_string()));
        }
    }

    #[test]
    fn startup_backends_have_distinct_kinds() {
        let kinds: Vec<BackendKind> = startup_backends()
            .iter()
            .map(|backend| backend.kind())
            .collect();
        let unique: HashSet<BackendKind> = kinds.iter().copied().collect();
        assert_eq!(kinds.len(), unique.len());
    }
}
