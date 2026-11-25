//! Admin API for OpenAPI/Swagger spec ingestion + retrieval.
//!
//! v1 supports OpenAPI 2.0 (Swagger), 3.0.x, 3.1.x, 3.2.x in JSON or YAML.

pub mod bounded_yaml;
pub mod external_refs;
pub mod extractor;
pub mod handlers;

// The binary target declares this module tree privately, while the library
// target intentionally exposes these imports to integration tests and custom
// consumers. Some binary-only feature profiles therefore see the re-exports as
// unused even though they are part of the library surface.
#[allow(unused_imports)]
pub use external_refs::{
    DefaultExternalDocumentLoader, EffectiveExternalRefPolicy, ExternalDocumentLoader,
    ExternalRefProcessPolicy, ExternalRefSnapshot, ExternalRefSpecExtension,
    MapExternalDocumentLoader, load_external_documents, parse_external_ref_extension,
};
#[allow(unused_imports)]
pub use extractor::{
    ExtractError, ExtractedBundle, SpecFormat, SpecMetadata, extract,
    extract_declared_proxy_plugin_association_ids, extract_with_external_refs,
    hash_resource_bundle,
};

/// Concurrent write-side API-spec codec jobs (upload compression/hashing and
/// stored-spec association recovery) admitted onto the blocking pool
/// process-wide. Kept separate from read-side `GET /api-specs/{id}/content`
/// conversion slots so viewer GET traffic can never starve namespace-locked
/// writes.
pub(crate) const MAX_CONCURRENT_SPEC_WRITE_CODEC_JOBS: usize = 4;

pub(crate) static SPEC_WRITE_CODEC_SLOTS: std::sync::LazyLock<
    std::sync::Arc<tokio::sync::Semaphore>,
> = std::sync::LazyLock::new(|| {
    std::sync::Arc::new(tokio::sync::Semaphore::new(
        MAX_CONCURRENT_SPEC_WRITE_CODEC_JOBS,
    ))
});

/// Compute the decompression cap for recovering associations from a stored spec
/// row given a resolved `admin_spec_max_body_size_mib` (2× body cap, floored at
/// 64 MiB) so deployments that raise the admission limit never falsely fail
/// association recovery, while untrusted DB `uncompressed_size` values remain
/// bounded.
pub(crate) fn stored_spec_assoc_decompress_cap_bytes(max_body_mib: usize) -> usize {
    const MIN_CAP_BYTES: usize = 64 * 1024 * 1024;
    max_body_mib
        .saturating_mul(2)
        .saturating_mul(1024)
        .saturating_mul(1024)
        .max(MIN_CAP_BYTES)
}

/// Parse a resolved `FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB` value into the
/// stored-spec association decompression cap, failing closed on invalid or zero
/// values rather than silently falling back to 25 MiB.
#[doc(hidden)]
#[allow(dead_code)]
pub fn stored_spec_assoc_decompress_cap_from_resolved(
    resolved: Option<&str>,
) -> Result<usize, String> {
    match resolved {
        Some(raw) => {
            let trimmed = raw.trim();
            let body_mib = trimmed.parse::<usize>().map_err(|error| {
                format!("invalid FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB value {trimmed:?}: {error}")
            })?;
            if body_mib == 0 {
                return Err(
                    "FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB must be at least 1 MiB".to_string()
                );
            }
            Ok(stored_spec_assoc_decompress_cap_bytes(body_mib))
        }
        None => Ok(stored_spec_assoc_decompress_cap_bytes(25)),
    }
}

/// Resolve the stored-spec association decompression cap from env / `ferrum.conf`
/// via [`crate::config::conf_file::resolve_ferrum_var_checked`], failing closed
/// on an invalid configured value or unreadable conf file.
pub(crate) fn resolve_stored_spec_assoc_decompress_cap_bytes() -> Result<usize, String> {
    let resolved = crate::config::conf_file::resolve_ferrum_var_checked(
        "FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB",
    )?;
    stored_spec_assoc_decompress_cap_from_resolved(resolved.as_deref())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredSpecAssocCacheKey {
    compressed_sha256: String,
    uncompressed_size: u64,
    spec_format: SpecFormat,
    cap: usize,
}

const STORED_SPEC_ASSOC_CACHE_CAPACITY: usize = 64;

type StoredSpecAssocCacheEntry = (
    StoredSpecAssocCacheKey,
    std::sync::Arc<std::collections::HashSet<String>>,
);
type StoredSpecAssocCache = std::sync::Mutex<std::collections::VecDeque<StoredSpecAssocCacheEntry>>;

static STORED_SPEC_ASSOC_CACHE: std::sync::LazyLock<StoredSpecAssocCache> =
    std::sync::LazyLock::new(|| {
        std::sync::Mutex::new(std::collections::VecDeque::with_capacity(
            STORED_SPEC_ASSOC_CACHE_CAPACITY,
        ))
    });

fn stored_spec_assoc_cache_key(
    spec: &crate::config::types::ApiSpec,
    max_cap: usize,
) -> Result<(StoredSpecAssocCacheKey, usize), String> {
    if spec.content_encoding != "gzip" {
        return Err(format!(
            "api_spec '{}' uses unsupported content_encoding '{}'",
            spec.id, spec.content_encoding
        ));
    }
    let cap = usize::try_from(spec.uncompressed_size)
        .map_err(|_| {
            format!(
                "api_spec '{}' has invalid uncompressed_size {}",
                spec.id, spec.uncompressed_size
            )
        })?
        .min(max_cap);
    let compressed_sha256 = crate::admin::spec_codec::sha256_hex(&spec.spec_content);
    Ok((
        StoredSpecAssocCacheKey {
            compressed_sha256,
            uncompressed_size: spec.uncompressed_size,
            spec_format: spec.spec_format,
            cap,
        },
        cap,
    ))
}

fn lookup_cached_stored_spec_assoc(
    key: &StoredSpecAssocCacheKey,
) -> Option<std::collections::HashSet<String>> {
    let guard = STORED_SPEC_ASSOC_CACHE.lock().ok()?;
    guard
        .iter()
        .rev()
        .find(|(k, _)| k == key)
        .map(|(_, ids)| (**ids).clone())
}

fn insert_cached_stored_spec_assoc(
    key: StoredSpecAssocCacheKey,
    ids: &std::collections::HashSet<String>,
) {
    if let Ok(mut guard) = STORED_SPEC_ASSOC_CACHE.lock() {
        if let Some(pos) = guard.iter().position(|(k, _)| k == &key) {
            guard.remove(pos);
        }
        if guard.len() >= STORED_SPEC_ASSOC_CACHE_CAPACITY {
            guard.pop_front();
        }
        guard.push_back((key, std::sync::Arc::new(ids.clone())));
    }
}

/// Recover the proxy/plugin associations explicitly declared by a stored API
/// spec using an explicit maximum decompression cap.
///
/// Fails closed on decompression or parse failure for gzip specs so replacement
/// never silently drops ownership recovery and leaves removed plugin
/// associations attached.
pub(crate) fn declared_proxy_plugin_association_ids_from_stored_spec_with_cap(
    spec: &crate::config::types::ApiSpec,
    max_cap: usize,
) -> Result<std::collections::HashSet<String>, String> {
    let (cache_key, cap) = stored_spec_assoc_cache_key(spec, max_cap)?;
    if let Some(cached) = lookup_cached_stored_spec_assoc(&cache_key) {
        return Ok(cached);
    }
    let body = crate::admin::spec_codec::decompress_gzip_capped(&spec.spec_content, cap).map_err(
        |error| {
            format!(
                "failed to decompress stored api_spec '{}' proxy plugin associations (cap={} bytes): {}",
                spec.id, cap, error
            )
        },
    )?;
    let ids: std::collections::HashSet<String> =
        extract_declared_proxy_plugin_association_ids(&body, Some(spec.spec_format))
            .map(|ids| ids.into_iter().collect())
            .map_err(|error| {
                format!(
                    "failed to parse stored api_spec '{}' proxy plugin associations: {}",
                    spec.id, error
                )
            })?;
    insert_cached_stored_spec_assoc(cache_key, &ids);
    Ok(ids)
}

/// Async, bounded blocking-pool version of [`hash_resource_bundle`].
///
/// Runs canonical serialization and SHA-256 hashing of an extracted bundle on
/// `tokio::task::spawn_blocking` under [`SPEC_WRITE_CODEC_SLOTS`] so Tokio
/// workers never stall hashing large generated plugin configurations.
pub(crate) async fn hash_resource_bundle_async(
    bundle: ExtractedBundle,
) -> Result<String, anyhow::Error> {
    let permit = std::sync::Arc::clone(&SPEC_WRITE_CODEC_SLOTS)
        .acquire_owned()
        .await
        .map_err(|_| anyhow::anyhow!("spec codec admission unavailable"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_resource_bundle(&bundle)
    })
    .await
    .map_err(|error| anyhow::anyhow!("resource bundle hash worker failed: {error}"))?
}

/// Async, bounded blocking-pool version of
/// [`declared_proxy_plugin_association_ids_from_stored_spec_with_cap`].
///
/// Acquires a permit from [`SPEC_WRITE_CODEC_SLOTS`] and computes the cache
/// key, verified cache lookup, and any required gzip decompression + parsing
/// inside `tokio::task::spawn_blocking` so Tokio workers never hash,
/// decompress, or parse large specs inline.
pub(crate) async fn declared_proxy_plugin_association_ids_from_stored_spec_async(
    spec: crate::config::types::ApiSpec,
    max_cap: Option<usize>,
) -> Result<std::collections::HashSet<String>, String> {
    if spec.content_encoding != "gzip" {
        return Err(format!(
            "api_spec '{}' uses unsupported content_encoding '{}'",
            spec.id, spec.content_encoding
        ));
    }
    if usize::try_from(spec.uncompressed_size).is_err() {
        return Err(format!(
            "api_spec '{}' has invalid uncompressed_size {}",
            spec.id, spec.uncompressed_size
        ));
    }
    let max_cap = match max_cap {
        Some(cap) => cap,
        None => resolve_stored_spec_assoc_decompress_cap_bytes()?,
    };
    let permit = std::sync::Arc::clone(&SPEC_WRITE_CODEC_SLOTS)
        .acquire_owned()
        .await
        .map_err(|_| "spec codec admission unavailable".to_string())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        declared_proxy_plugin_association_ids_from_stored_spec_with_cap(&spec, max_cap)
    })
    .await
    .map_err(|error| format!("stored api_spec association recovery worker failed: {error}"))?
}
