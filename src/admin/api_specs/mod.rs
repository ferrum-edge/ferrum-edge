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

/// Recover the proxy/plugin associations explicitly declared by a stored API
/// spec. Replacement uses this set to distinguish spec-declared associations
/// from manual associations that must survive PUT.
///
/// Stored metadata is best-effort here to preserve the existing replacement
/// contract: an unsupported encoding or unreadable legacy document is warned
/// about and treated as declaring no external associations.
pub(crate) fn declared_proxy_plugin_association_ids_from_stored_spec(
    spec: &crate::config::types::ApiSpec,
) -> std::collections::HashSet<String> {
    if spec.content_encoding != "gzip" {
        tracing::warn!(
            "api_spec '{}' uses unsupported content_encoding '{}'",
            spec.id,
            spec.content_encoding
        );
        return std::collections::HashSet::new();
    }
    /// Upper bound for best-effort decompression of stored specs during PUT
    /// association recovery so an untrusted or corrupt `uncompressed_size` DB
    /// value can never disable the gzip-bomb cap.
    const MAX_STORED_SPEC_ASSOC_DECOMPRESS_BYTES: usize = 64 * 1024 * 1024;
    let cap = usize::try_from(spec.uncompressed_size)
        .unwrap_or(MAX_STORED_SPEC_ASSOC_DECOMPRESS_BYTES)
        .min(MAX_STORED_SPEC_ASSOC_DECOMPRESS_BYTES);
    let body = match crate::admin::spec_codec::decompress_gzip_capped(&spec.spec_content, cap) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(
                "failed to decompress stored api_spec '{}' proxy plugin associations: {}",
                spec.id,
                error
            );
            return std::collections::HashSet::new();
        }
    };
    match extract_declared_proxy_plugin_association_ids(&body, Some(spec.spec_format)) {
        Ok(ids) => ids.into_iter().collect(),
        Err(error) => {
            tracing::warn!(
                "failed to parse stored api_spec '{}' proxy plugin associations: {}",
                spec.id,
                error
            );
            std::collections::HashSet::new()
        }
    }
}
