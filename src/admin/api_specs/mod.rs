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

/// Compute the decompression cap for recovering associations from a stored spec
/// row, honoring `FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB` (2× body cap, floored at
/// 64 MiB) so deployments that raise the admission limit never falsely fail
/// association recovery, while untrusted DB `uncompressed_size` values remain
/// bounded.
fn max_stored_spec_assoc_decompress_bytes() -> usize {
    const MIN_CAP_BYTES: usize = 64 * 1024 * 1024;
    let body_mib = std::env::var("FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(25);
    body_mib
        .saturating_mul(2)
        .saturating_mul(1024)
        .saturating_mul(1024)
        .max(MIN_CAP_BYTES)
}

/// Recover the proxy/plugin associations explicitly declared by a stored API
/// spec. Replacement uses this set to distinguish spec-declared associations
/// from manual associations that must survive PUT.
///
/// Fails closed on decompression or parse failure for gzip specs so replacement
/// never silently drops ownership recovery and leaves removed plugin
/// associations attached.
pub(crate) fn declared_proxy_plugin_association_ids_from_stored_spec(
    spec: &crate::config::types::ApiSpec,
) -> Result<std::collections::HashSet<String>, String> {
    if spec.content_encoding != "gzip" {
        return Err(format!(
            "api_spec '{}' uses unsupported content_encoding '{}'",
            spec.id, spec.content_encoding
        ));
    }
    let max_cap = max_stored_spec_assoc_decompress_bytes();
    let cap = usize::try_from(spec.uncompressed_size)
        .map_err(|_| {
            format!(
                "api_spec '{}' has invalid uncompressed_size {}",
                spec.id, spec.uncompressed_size
            )
        })?
        .min(max_cap);
    let body = crate::admin::spec_codec::decompress_gzip_capped(&spec.spec_content, cap).map_err(
        |error| {
            format!(
                "failed to decompress stored api_spec '{}' proxy plugin associations (cap={} bytes): {}",
                spec.id, cap, error
            )
        },
    )?;
    extract_declared_proxy_plugin_association_ids(&body, Some(spec.spec_format))
        .map(|ids| ids.into_iter().collect())
        .map_err(|error| {
            format!(
                "failed to parse stored api_spec '{}' proxy plugin associations: {}",
                spec.id, error
            )
        })
}
