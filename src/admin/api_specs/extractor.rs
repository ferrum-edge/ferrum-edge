//! OpenAPI/Swagger spec parser and Ferrum resource extractor.
//!
//! Parses an OpenAPI 2.0 (Swagger), 3.0.x, 3.1.x, or 3.2.x spec document
//! (JSON or YAML) and extracts Ferrum-native resources from the
//! `x-ferrum-proxy`, `x-ferrum-upstream`, and `x-ferrum-plugins` extensions.
//!
//! # Extension protocol
//!
//! - `x-ferrum-proxy` (required): serialised [`Proxy`] object.
//! - `x-ferrum-upstream` (optional): serialised [`Upstream`] object.
//! - `x-ferrum-plugins` (optional): array of serialised [`PluginConfig`] objects.
//! - `x-ferrum-consumers` (forbidden): rejected with [`ExtractError::ConsumerExtensionNotAllowed`].
//!
//! The caller's `namespace` overrides any namespace embedded in the spec.
//! All plugins are forced to `scope = proxy` and `proxy_id = proxy.id`.

// Re-export so Wave 3 handlers can `use crate::admin::api_specs::SpecFormat`
// without knowing that the canonical definition lives in config::types.
pub use crate::config::types::SpecFormat;
use crate::config::types::{
    MAX_OPENAPI_VALIDATOR_CONFIG_DEPTH, MAX_OPENAPI_VALIDATOR_CONFIG_SIZE,
    OPENAPI_VALIDATOR_DEFAULT_CONTENT_TYPES, json_depth, validate_resource_id,
};
use crate::config::types::{PluginAssociation, PluginConfig, PluginScope, Proxy, Upstream};
use crate::util::media_type::is_concrete_http_media_type;
use chrono::Utc;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use url::Url;

use super::external_refs::{
    EffectiveExternalRefPolicy, ExternalDocumentLoader, ExternalRefProcessPolicy,
    LoadedExternalDocument, MapExternalDocumentLoader, load_external_documents,
    parse_external_ref_extension, redact_reference,
};

/// HTTP method keys counted when computing `operation_count`.
const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "delete", "options", "head", "patch", "trace",
];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Resources extracted from an OpenAPI spec document.
#[derive(Debug, Clone)]
pub struct ExtractedBundle {
    pub proxy: Proxy,
    pub upstream: Option<Upstream>,
    pub plugins: Vec<PluginConfig>,
}

/// Metadata about the OpenAPI spec document itself (not the extracted resources).
#[derive(Debug, Clone)]
pub struct SpecMetadata {
    /// Spec language version: `"2.0"`, `"3.0.3"`, `"3.1.0"`, `"3.2.0"`, etc.
    pub version: String,
    pub format: SpecFormat,
    /// `info.title` from the spec, if present and a string.
    pub title: Option<String>,
    /// `info.version` from the spec, if present and a string.
    pub info_version: Option<String>,
    // --- Tier 1 metadata (Wave 5) ---
    /// `info.description` truncated at 4096 bytes (UTF-8-safe).
    pub description: Option<String>,
    /// `info.contact.name`
    pub contact_name: Option<String>,
    /// `info.contact.email`
    pub contact_email: Option<String>,
    /// `info.license.name`
    pub license_name: Option<String>,
    /// `info.license.identifier` (3.1+) or `info.license.url` fallback.
    pub license_identifier: Option<String>,
    /// Top-level `tags[].name`, de-duplicated and sorted.
    pub tags: Vec<String>,
    /// Server URLs (`servers[].url` for 3.x; constructed from `schemes + host + basePath` for 2.0).
    pub server_urls: Vec<String>,
    /// Count of HTTP method keys across all `paths.*` entries.
    pub operation_count: u32,
    /// Immutable admission snapshot of external documents used for `$ref` resolution.
    ///
    /// `None` when external-ref resolution stayed disabled (fail-closed default).
    /// Set when the effective policy enables loading, even if no external documents
    /// were reachable.
    pub external_ref_snapshot: Option<crate::admin::api_specs::external_refs::ExternalRefSnapshot>,
}

/// Errors that can occur during spec extraction.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    #[error("invalid YAML: {0}")]
    InvalidYaml(String),
    #[error("unknown spec version (expected 'swagger: \"2.0\"' or 'openapi: \"3.x.y\"')")]
    UnknownVersion,
    #[error("missing required x-ferrum-proxy extension at root")]
    MissingProxyExtension,
    #[error("malformed {which} extension: {error}")]
    MalformedExtension { which: &'static str, error: String },
    #[error("consumers cannot be created via spec; use POST /consumers")]
    ConsumerExtensionNotAllowed,
    #[error(
        "plugin {plugin_id}: only proxy-scoped plugins are allowed in specs (got scope='{scope}')"
    )]
    PluginInvalidScope { plugin_id: String, scope: String },
    #[error(
        "plugin {plugin_id}: proxy_id mismatch (plugin has '{plugin_proxy_id}', spec has '{spec_proxy_id}')"
    )]
    PluginProxyIdMismatch {
        plugin_id: String,
        plugin_proxy_id: String,
        spec_proxy_id: String,
    },
    #[error("plugin {plugin_id} contains forbidden credential/consumer key '{key}'")]
    PluginContainsCredentials { plugin_id: String, key: String },
    #[error(
        "proxy {proxy_id}: upstream_id '{proxy_upstream_id}' conflicts with x-ferrum-upstream id '{spec_upstream_id}'"
    )]
    ProxyUpstreamIdMismatch {
        proxy_id: String,
        proxy_upstream_id: String,
        spec_upstream_id: String,
    },
    /// Tag name contains a character that would cause false LIKE matches in the
    /// SQL `has_tag` filter (`"`, `%`, `_`, or `\`).  Tag names with these
    /// characters are rejected at extraction time rather than escaping them at
    /// query time, because tag names are short identifiers and these characters
    /// have no legitimate use in them.  Note that `_` is also a single-character
    /// SQL LIKE wildcard, so `?has_tag=api_v1` would otherwise falsely match
    /// `apixv1`. See `db_loader.rs` `list_api_specs` `has_tag` branch for the
    /// matching LIKE pattern.
    #[error("tag '{name}' contains forbidden character '{char}' (\", %, _, or \\\\)")]
    InvalidTagName { name: String, char: char },
    #[error("external $ref '{reference}' is not supported in x-ferrum-validate schemas")]
    UnsupportedExternalRef { reference: String },
    #[error("schema reference error: {0}")]
    SchemaReference(String),
    #[error("schema reference depth exceeded while resolving '{location}'")]
    SchemaTooDeep { location: String },
    /// A local `$ref` chain re-entered a target that is still being expanded.
    ///
    /// `path` is the chain of `$ref` literals from the outermost reference to
    /// the one that closed the cycle. Those literals come from the submitted
    /// document and name document structure only, so the message carries no
    /// resolver-internal state and no operator secret.
    #[error("schema reference cycle detected: {path}")]
    SchemaReferenceCycle { path: String },
    #[error("resolved schema exceeds the expansion limit while resolving '{location}'")]
    SchemaTooLarge { location: String },
}

// ---------------------------------------------------------------------------
// OpenAPI 3.x version-string matcher
// ---------------------------------------------------------------------------

/// Returns `true` iff `s` is a valid SemVer string for OpenAPI 3.x.
fn is_openapi3_version(s: &str) -> bool {
    semver::Version::parse(s).is_ok_and(|version| version.major == 3)
}

/// Plugin config keys that are forbidden inside a plugin's `config` value.
/// The walk is recursive; finding any of these keys at any depth is an error.
const FORBIDDEN_CONFIG_KEYS: &[&str] = &[
    "credentials",
    "keyauth",
    "basicauth",
    "jwt",
    "hmac",
    "mtls",
    "consumer",
    "consumer_id",
    "consumer_groups",
    "consumers",
];

// ---------------------------------------------------------------------------
// Shared metadata admission bounds (extraction truncates; restore rejects)
// ---------------------------------------------------------------------------

/// Maximum UTF-8 byte length for stored `info.title`.
pub(crate) const MAX_SPEC_TITLE_BYTES: usize = 1024;
/// Maximum UTF-8 byte length for stored `info.version`.
pub(crate) const MAX_SPEC_INFO_VERSION_BYTES: usize = 256;
/// Maximum UTF-8 byte length for stored `info.description`.
pub(crate) const MAX_SPEC_DESCRIPTION_BYTES: usize = 4096;
/// Maximum UTF-8 byte length for stored `info.contact.name`.
pub(crate) const MAX_SPEC_CONTACT_NAME_BYTES: usize = 256;
/// Maximum UTF-8 byte length for stored `info.contact.email` (RFC 5321).
pub(crate) const MAX_SPEC_CONTACT_EMAIL_BYTES: usize = 320;
/// Maximum UTF-8 byte length for stored `info.license.name`.
pub(crate) const MAX_SPEC_LICENSE_NAME_BYTES: usize = 256;
/// Maximum UTF-8 byte length for stored license identifier/URL.
pub(crate) const MAX_SPEC_LICENSE_IDENTIFIER_BYTES: usize = 128;
/// Maximum UTF-8 byte length for one stored tag name.
pub(crate) const MAX_SPEC_TAG_BYTES: usize = 128;
/// Maximum number of stored tag names after sort/dedup.
pub(crate) const MAX_SPEC_TAGS: usize = 64;
/// Maximum UTF-8 byte length for one stored server URL.
pub(crate) const MAX_SPEC_SERVER_URL_BYTES: usize = 2048;
/// Maximum number of stored server URLs.
pub(crate) const MAX_SPEC_SERVER_URLS: usize = 32;

/// Return the first character in `tag` that would break SQL `has_tag` LIKE
/// semantics (`"`, `%`, `_`, or `\`), if any.
///
/// Shared by extraction, list-query admission, and restore metadata checks so
/// the whitelist cannot drift across those paths.
pub(crate) fn api_spec_tag_forbidden_char(tag: &str) -> Option<char> {
    tag.chars().find(|c| matches!(c, '"' | '%' | '_' | '\\'))
}

/// Fail-closed validation of **stored** API-spec metadata bounds.
///
/// Extraction truncates oversize source fields to these limits; restore must
/// reject wire values that exceed them (or violate tag cardinality / sort /
/// whitelist invariants) so a crafted backup cannot persist metadata that
/// ordinary POST/PUT ingestion forbids. Error strings intentionally omit the
/// hostile field values themselves.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_stored_api_spec_metadata(
    title: Option<&str>,
    info_version: Option<&str>,
    description: Option<&str>,
    contact_name: Option<&str>,
    contact_email: Option<&str>,
    license_name: Option<&str>,
    license_identifier: Option<&str>,
    tags: &[String],
    server_urls: &[String],
) -> Result<(), &'static str> {
    let within = |value: Option<&str>, max: usize| value.is_none_or(|s| s.len() <= max);
    if !within(title, MAX_SPEC_TITLE_BYTES) {
        return Err("title exceeds maximum length");
    }
    if !within(info_version, MAX_SPEC_INFO_VERSION_BYTES) {
        return Err("info_version exceeds maximum length");
    }
    if !within(description, MAX_SPEC_DESCRIPTION_BYTES) {
        return Err("description exceeds maximum length");
    }
    if !within(contact_name, MAX_SPEC_CONTACT_NAME_BYTES) {
        return Err("contact_name exceeds maximum length");
    }
    if !within(contact_email, MAX_SPEC_CONTACT_EMAIL_BYTES) {
        return Err("contact_email exceeds maximum length");
    }
    if !within(license_name, MAX_SPEC_LICENSE_NAME_BYTES) {
        return Err("license_name exceeds maximum length");
    }
    if !within(license_identifier, MAX_SPEC_LICENSE_IDENTIFIER_BYTES) {
        return Err("license_identifier exceeds maximum length");
    }
    if tags.len() > MAX_SPEC_TAGS {
        return Err("tags exceed maximum cardinality");
    }
    for tag in tags {
        if tag.len() > MAX_SPEC_TAG_BYTES {
            return Err("tag exceeds maximum length");
        }
        if api_spec_tag_forbidden_char(tag).is_some() {
            return Err("tag contains forbidden character");
        }
    }
    // Extraction always sorts + dedups before persist; restore must preserve
    // that invariant for list/filter surfaces that assume unique membership.
    for window in tags.windows(2) {
        if window[0] >= window[1] {
            return Err("tags must be sorted and de-duplicated");
        }
    }
    if server_urls.len() > MAX_SPEC_SERVER_URLS {
        return Err("server_urls exceed maximum cardinality");
    }
    for url in server_urls {
        if url.len() > MAX_SPEC_SERVER_URL_BYTES {
            return Err("server_url exceeds maximum length");
        }
    }
    Ok(())
}

/// Parse `body` under a **declared** format using the same bounded document
/// parser as ingestion and return the spec-language version it declares.
///
/// This admits JSON/YAML syntax (plus the source-tree node cap and bounded
/// YAML anchor/alias expansion) and the same root `swagger`/`openapi` version
/// detection [`extract`] performs, so a document that declares no supported
/// OpenAPI/Swagger version is rejected. It does **not** extract resources,
/// re-resolve `$ref`s, or regenerate config — restore must keep historical
/// backups restorable without replaying extraction.
pub(crate) fn parse_declared_spec_document_version(
    body: &[u8],
    declared_format: SpecFormat,
) -> Result<String, ExtractError> {
    let (root, _) = parse_root_document(body, Some(declared_format))?;
    detect_version(&root)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Sniff whether `body` looks like JSON or YAML by inspecting the first
/// non-whitespace byte.
///
/// JSON documents always start with `{` or `[`; YAML docs start with
/// a letter or `---`. The byte sniff is a best-effort heuristic; the full
/// parse will produce a more precise error if the bytes are invalid.
pub fn autodetect_format(body: &[u8]) -> SpecFormat {
    let first = body.iter().find(|&&b| !b.is_ascii_whitespace());
    match first {
        Some(b'{') | Some(b'[') => SpecFormat::Json,
        _ => SpecFormat::Yaml,
    }
}

/// Parse `body` as an OpenAPI spec document and extract Ferrum resources.
///
/// Uses the fail-closed default external-ref policy (resolution disabled) and
/// an empty in-memory loader. Prefer [`extract_with_external_refs`] when the
/// process gate and per-spec extension may enable cross-document `$ref`s.
///
/// # Arguments
///
/// * `body` – raw bytes of the spec document.
/// * `declared_format` – caller-supplied format hint (`Content-Type` header).
///   When `None`, [`autodetect_format`] is used.
/// * `namespace` – the namespace to stamp on every extracted resource,
///   overriding whatever the spec document declares.
///
/// # Returns
///
/// `(bundle, metadata)` on success, or an [`ExtractError`] describing the
/// first problem encountered.
// The binary target compiles this public library module privately and uses the
// policy-aware entry point directly; integration tests retain this compatibility
// entry point for the default fail-closed behavior.
#[allow(dead_code)]
pub fn extract(
    body: &[u8],
    declared_format: Option<SpecFormat>,
    namespace: &str,
) -> Result<(ExtractedBundle, SpecMetadata), ExtractError> {
    extract_with_external_refs(
        body,
        declared_format,
        namespace,
        &ExternalRefProcessPolicy::default(),
        &MapExternalDocumentLoader::default(),
    )
}

/// Parse `body` as an OpenAPI spec and extract Ferrum resources, optionally
/// resolving external / cross-document `$ref`s under `process_policy`.
///
/// Absent or disabled policy keeps the historical fail-closed
/// [`ExtractError::UnsupportedExternalRef`] contract. When both the process
/// gate and `x-ferrum-external-refs` enable resolution, referenced documents
/// are loaded through `loader` at admission time and recorded on
/// [`SpecMetadata::external_ref_snapshot`].
pub fn extract_with_external_refs(
    body: &[u8],
    declared_format: Option<SpecFormat>,
    namespace: &str,
    process_policy: &ExternalRefProcessPolicy,
    loader: &dyn ExternalDocumentLoader,
) -> Result<(ExtractedBundle, SpecMetadata), ExtractError> {
    let (root, actual_format) = parse_root_document(body, declared_format)?;

    // --- Version detection -----------------------------------------------
    let version = detect_version(&root)?;

    // --- External / cross-document $ref policy ---------------------------
    let extension = parse_external_ref_extension(&root)?;
    let effective = EffectiveExternalRefPolicy::compose(process_policy, extension.as_ref())?;
    let (external_docs, external_ref_snapshot) = if effective.enabled {
        let (docs, snapshot) = load_external_documents(&root, &effective, loader)?;
        (docs, Some(snapshot))
    } else {
        (HashMap::new(), None)
    };

    // --- info.title / info.version ---------------------------------------
    // Both fields are truncated at UTF-8 character boundaries so an operator
    // with a 25 MiB spec cannot store a 1 MiB title or version string.
    // `description` was already bounded to 4096 bytes in `extract_spec_metadata`.
    let title = root
        .get("info")
        .and_then(|i| i.get("title"))
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, MAX_SPEC_TITLE_BYTES));

    let info_version = root
        .get("info")
        .and_then(|i| i.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, MAX_SPEC_INFO_VERSION_BYTES));

    // --- Tier 1 metadata (Wave 5) ----------------------------------------
    let tier1 = extract_spec_metadata(&root, &version);

    // --- Tag name validation ---------------------------------------------
    // SAFETY-CRITICAL CROSS-FILE INVARIANT:
    // The SQL `has_tag` filter in src/config/db_loader.rs uses a bare LIKE
    // pattern (`tags LIKE '%"<tag>"%'`) that embeds tag names directly without
    // an ESCAPE clause.  Tag names containing `"`, `%`, `_`, or `\` would
    // produce false matches or wildcard matches against the stored JSON-array
    // column.  In particular, `_` is the SQL LIKE single-character wildcard:
    // without rejecting it, `?has_tag=api_v1` would falsely match `apixv1`.
    // We reject those characters here to keep the LIKE filter correct.
    // MongoDB uses native array membership (`filter_doc.insert("tags", tag)`)
    // and is unaffected, but we still reject these characters for consistency.
    //
    // If you change or extend this tag-character whitelist, also update:
    //   src/config/db_loader.rs  — list_api_specs, has_tag branch (comment there)
    //   docs/api_specs.md        — "Tag-name rules" section
    //   validate_stored_api_spec_metadata — restore admission path
    for tag in &tier1.tags {
        if let Some(ch) = api_spec_tag_forbidden_char(tag) {
            return Err(ExtractError::InvalidTagName {
                name: tag.clone(),
                char: ch,
            });
        }
    }

    // --- x-ferrum-consumers guard ----------------------------------------
    if root.get("x-ferrum-consumers").is_some() {
        return Err(ExtractError::ConsumerExtensionNotAllowed);
    }

    // --- x-ferrum-proxy (required) ---------------------------------------
    let proxy_val = root
        .get("x-ferrum-proxy")
        .ok_or(ExtractError::MissingProxyExtension)?;

    let mut proxy: Proxy = serde_json::from_value(proxy_val.clone()).map_err(|e| {
        ExtractError::MalformedExtension {
            which: "x-ferrum-proxy",
            error: e.to_string(),
        }
    })?;
    proxy.namespace = namespace.to_string();

    // --- ID validation for proxy (BEFORE auto-linking) ----------------------
    // Non-empty id → validate format; malformed ids are rejected here rather
    // than at the DB layer so the error message is actionable.
    // Empty id → leave empty; the route handler (assign_ids_for_post /
    // assign_ids_for_put) is responsible for assigning or reusing IDs so that
    // PUT idempotency works correctly.
    if !proxy.id.is_empty()
        && let Err(e) = validate_resource_id(&proxy.id)
    {
        return Err(ExtractError::MalformedExtension {
            which: "x-ferrum-proxy",
            error: format!("invalid id: {}", e),
        });
    }

    // --- x-ferrum-upstream (optional) ------------------------------------
    let upstream = if let Some(up_val) = root.get("x-ferrum-upstream") {
        let mut up: Upstream = serde_json::from_value(up_val.clone()).map_err(|e| {
            ExtractError::MalformedExtension {
                which: "x-ferrum-upstream",
                error: e.to_string(),
            }
        })?;
        up.namespace = namespace.to_string();

        // --- ID validation for upstream (BEFORE auto-linking) ---------------
        // Empty id → leave empty; handler assigns / reuses IDs.
        if !up.id.is_empty()
            && let Err(e) = validate_resource_id(&up.id)
        {
            return Err(ExtractError::MalformedExtension {
                which: "x-ferrum-upstream",
                error: format!("invalid id: {}", e),
            });
        }

        Some(up)
    } else {
        None
    };

    // --- Auto-link upstream to proxy ----------------------------------------
    // If the spec includes an upstream, set proxy.upstream_id to the upstream's
    // id unless the operator already pinned a different one (which is an error).
    if let Some(ref u) = upstream {
        match proxy.upstream_id.as_deref() {
            None => proxy.upstream_id = Some(u.id.clone()),
            Some(existing) if existing == u.id => {} // explicit + same → ok
            Some(existing) => {
                return Err(ExtractError::ProxyUpstreamIdMismatch {
                    proxy_id: proxy.id.clone(),
                    proxy_upstream_id: existing.to_string(),
                    spec_upstream_id: u.id.clone(),
                });
            }
        }
    }

    // --- x-ferrum-plugins (optional array) --------------------------------
    let mut plugins = if let Some(plugins_val) = root.get("x-ferrum-plugins") {
        let arr = plugins_val
            .as_array()
            .ok_or_else(|| ExtractError::MalformedExtension {
                which: "x-ferrum-plugins",
                error: "expected an array".to_string(),
            })?;

        let mut out = Vec::with_capacity(arr.len());
        for entry in arr {
            // Default scope to "proxy" when the spec omits it — proxy-scope
            // is the only allowed value here (enforced below), so requiring
            // explicit `scope: proxy` everywhere would just be friction.
            // Explicit non-proxy scopes still fail downstream with a clear
            // error.
            let mut entry_with_default = entry.clone();
            if let Some(map) = entry_with_default.as_object_mut() {
                map.entry("scope".to_string())
                    .or_insert(serde_json::Value::String("proxy".to_string()));
            }

            let mut pc: PluginConfig = serde_json::from_value(entry_with_default).map_err(|e| {
                ExtractError::MalformedExtension {
                    which: "x-ferrum-plugins",
                    error: e.to_string(),
                }
            })?;

            // --- ID validation for plugin (BEFORE auto-linking) -------------
            // Empty id → leave empty; handler assigns / reuses IDs.
            if !pc.id.is_empty()
                && let Err(e) = validate_resource_id(&pc.id)
            {
                return Err(ExtractError::MalformedExtension {
                    which: "x-ferrum-plugins",
                    error: format!("invalid id: {}", e),
                });
            }

            // Scope must be proxy (or absent/defaulted to proxy).
            if pc.scope != PluginScope::Proxy {
                let scope_str = match pc.scope {
                    PluginScope::Global => "global".to_string(),
                    PluginScope::ProxyGroup => "proxy_group".to_string(),
                    PluginScope::Proxy => "proxy".to_string(),
                };
                return Err(ExtractError::PluginInvalidScope {
                    plugin_id: pc.id,
                    scope: scope_str,
                });
            }

            // proxy_id must be absent or match the spec's proxy id.
            if let Some(ref pid) = pc.proxy_id
                && pid != &proxy.id
            {
                return Err(ExtractError::PluginProxyIdMismatch {
                    plugin_id: pc.id,
                    plugin_proxy_id: pid.clone(),
                    spec_proxy_id: proxy.id.clone(),
                });
            }

            // Walk config for forbidden credential / consumer keys.
            if let Some(key) = find_forbidden_key_for_plugin(&pc.plugin_name, &pc.config) {
                return Err(ExtractError::PluginContainsCredentials {
                    plugin_id: pc.id,
                    key: key.to_string(),
                });
            }

            // Reject duplicate non-empty plugin IDs within the same spec.
            if !pc.id.is_empty()
                && out
                    .iter()
                    .any(|existing: &PluginConfig| existing.id == pc.id)
            {
                return Err(ExtractError::MalformedExtension {
                    which: "x-ferrum-plugins",
                    error: format!("duplicate plugin id '{}'", pc.id),
                });
            }

            // Stamp namespace and link to proxy.
            pc.namespace = namespace.to_string();
            pc.proxy_id = Some(proxy.id.clone());

            out.push(pc);
        }
        out
    } else {
        Vec::new()
    };

    if let Some(validate_ext) = parse_x_ferrum_validate_extension(&root)? {
        let operations = extract_operation_schemas(
            &root,
            &version,
            proxy.listen_path.as_deref(),
            &effective.document_base,
            &external_docs,
        )?;
        auto_inject_openapi_validator(
            &mut plugins,
            &proxy,
            namespace,
            validate_ext,
            operations,
            &version,
        )?;
    }

    // --- Build proxy.plugins association list (Fix 2) -----------------------
    // The PluginCache only instantiates plugins whose IDs appear in the proxy's
    // `plugins` association list (junction table). Without this step, imported
    // plugins are stored in plugin_configs but never run.
    // Preserve any associations the operator wrote into x-ferrum-proxy.plugins
    // directly (e.g. associating an existing global plugin), then add the
    // spec-extracted ones.
    {
        let mut associations = std::mem::take(&mut proxy.plugins);
        for plugin in &plugins {
            if !associations.iter().any(|a| a.plugin_config_id == plugin.id) {
                associations.push(PluginAssociation {
                    plugin_config_id: plugin.id.clone(),
                });
            }
        }
        proxy.plugins = associations;
    }

    let metadata = SpecMetadata {
        version,
        format: actual_format,
        title,
        info_version,
        description: tier1.description,
        contact_name: tier1.contact_name,
        contact_email: tier1.contact_email,
        license_name: tier1.license_name,
        license_identifier: tier1.license_identifier,
        tags: tier1.tags,
        server_urls: tier1.server_urls,
        operation_count: tier1.operation_count,
        external_ref_snapshot,
    };

    Ok((
        ExtractedBundle {
            proxy,
            upstream,
            plugins,
        },
        metadata,
    ))
}

/// Return plugin IDs explicitly listed in `x-ferrum-proxy.plugins`.
///
/// This deliberately ignores associations auto-added from `x-ferrum-plugins`.
/// Replacement code uses it to distinguish associations owned by the previous
/// spec document from associations an operator added later through direct CRUD.
pub fn extract_declared_proxy_plugin_association_ids(
    body: &[u8],
    declared_format: Option<SpecFormat>,
) -> Result<Vec<String>, ExtractError> {
    let (root, _) = parse_root_document(body, declared_format)?;
    let Some(proxy_val) = root.get("x-ferrum-proxy") else {
        return Ok(Vec::new());
    };
    let Some(plugins_val) = proxy_val.get("plugins") else {
        return Ok(Vec::new());
    };
    let arr = plugins_val
        .as_array()
        .ok_or_else(|| ExtractError::MalformedExtension {
            which: "x-ferrum-proxy.plugins",
            error: "expected an array".to_string(),
        })?;

    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let assoc: PluginAssociation = serde_json::from_value(entry.clone()).map_err(|e| {
            ExtractError::MalformedExtension {
                which: "x-ferrum-proxy.plugins",
                error: e.to_string(),
            }
        })?;
        if !assoc.plugin_config_id.is_empty() && !out.iter().any(|id| id == &assoc.plugin_config_id)
        {
            out.push(assoc.plugin_config_id);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Public helpers — metadata extraction + resource hashing
// ---------------------------------------------------------------------------

/// Intermediate result from [`extract_spec_metadata`].
pub struct ExtractedMetadata {
    pub description: Option<String>,
    pub contact_name: Option<String>,
    pub contact_email: Option<String>,
    pub license_name: Option<String>,
    pub license_identifier: Option<String>,
    pub tags: Vec<String>,
    pub server_urls: Vec<String>,
    pub operation_count: u32,
}

fn parse_x_ferrum_validate_extension(root: &Value) -> Result<Option<Value>, ExtractError> {
    let Some(value) = root.get("x-ferrum-validate") else {
        return Ok(None);
    };
    match value {
        Value::Bool(true) => Ok(Some(json!({}))),
        Value::Bool(false) | Value::Null => Ok(None),
        Value::Object(_) => Ok(Some(value.clone())),
        other => Err(ExtractError::MalformedExtension {
            which: "x-ferrum-validate",
            error: format!("expected true, false, or object; got {other}"),
        }),
    }
}

fn auto_inject_openapi_validator(
    plugins: &mut Vec<PluginConfig>,
    proxy: &Proxy,
    namespace: &str,
    validate_ext: Value,
    operations: Vec<Value>,
    version: &str,
) -> Result<(), ExtractError> {
    let mut config = Map::new();
    config.insert(
        "enforcement_mode".to_string(),
        Value::String("block".to_string()),
    );
    config.insert("validate_request".to_string(), Value::Bool(true));
    config.insert("validate_response".to_string(), Value::Bool(true));
    config.insert(
        "request_content_types".to_string(),
        json!(OPENAPI_VALIDATOR_DEFAULT_CONTENT_TYPES),
    );
    config.insert(
        "response_content_types".to_string(),
        json!(OPENAPI_VALIDATOR_DEFAULT_CONTENT_TYPES),
    );
    config.insert("fail_on_unknown_operation".to_string(), Value::Bool(true));
    config.insert(
        "fail_on_missing_response_schema".to_string(),
        Value::Bool(false),
    );
    config.insert(
        "schema_draft".to_string(),
        Value::String(schema_draft_for_openapi(version)),
    );
    apply_validate_extension(&mut config, validate_ext)?;
    config.insert("operations".to_string(), Value::Array(operations));

    let auto_config = Value::Object(config);
    if let Some(existing) = plugins
        .iter_mut()
        .find(|plugin| plugin.plugin_name == "openapi_validator")
    {
        let merged = merge_openapi_validator_config(auto_config, &existing.config)?;
        validate_openapi_validator_config_budget(&merged)?;
        existing.config = merged;
        return Ok(());
    }

    validate_openapi_validator_config_budget(&auto_config)?;
    let now = Utc::now();
    plugins.push(PluginConfig {
        id: String::new(),
        plugin_name: "openapi_validator".to_string(),
        namespace: namespace.to_string(),
        config: auto_config,
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy.id.clone()),
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    });
    Ok(())
}

fn schema_draft_for_openapi(version: &str) -> String {
    if version == "2.0" || version.starts_with("3.0.") {
        "draft7".to_string()
    } else {
        "draft2020-12".to_string()
    }
}

fn validate_openapi_validator_config_budget(config: &Value) -> Result<(), ExtractError> {
    let size = serde_json::to_vec(config)
        .map_err(|error| ExtractError::MalformedExtension {
            which: "x-ferrum-validate",
            error: format!("generated openapi_validator config could not be serialized: {error}"),
        })?
        .len();
    if size > MAX_OPENAPI_VALIDATOR_CONFIG_SIZE {
        return Err(ExtractError::MalformedExtension {
            which: "x-ferrum-validate",
            error: format!(
                "generated openapi_validator config must not exceed {MAX_OPENAPI_VALIDATOR_CONFIG_SIZE} bytes (got {size})"
            ),
        });
    }
    let depth = json_depth(config);
    if depth > MAX_OPENAPI_VALIDATOR_CONFIG_DEPTH {
        return Err(ExtractError::MalformedExtension {
            which: "x-ferrum-validate",
            error: format!(
                "generated openapi_validator config depth must not exceed {MAX_OPENAPI_VALIDATOR_CONFIG_DEPTH} (got {depth})"
            ),
        });
    }
    Ok(())
}

/// Exhaustive `x-ferrum-validate` object keys.
///
/// The extension is a fixed-field object: an unrecognized key used to be copied
/// verbatim into the generated plugin config, so a typo produced a plugin that
/// constructed successfully with the weaker default still in force
/// (GHSA-692x-352q-6gm8). `operations` is regenerated from the document and is
/// rejected here rather than silently ignored.
const X_FERRUM_VALIDATE_KEYS: &[&str] = &[
    "mode",
    "request",
    "response",
    "validate_request",
    "validate_response",
    "bypass",
    "fail_on_unknown_operation",
    "fail_on_missing_response_schema",
    "max_body_bytes",
    "error_response",
    "error_truncate_chars",
];
const X_FERRUM_VALIDATE_SIDE_KEYS: &[&str] = &["enabled", "content_types"];
const OPENAPI_VALIDATOR_BYPASS_KEYS: &[&str] = &["paths", "methods", "consumers", "header_present"];

fn reject_unknown_validate_keys(
    object: &Map<String, Value>,
    path: &str,
    allowed: &[&str],
) -> Result<(), ExtractError> {
    crate::util::unknown_keys::reject_unknown_keys(object, path, allowed, "").map_err(|error| {
        ExtractError::MalformedExtension {
            which: "x-ferrum-validate",
            error,
        }
    })
}

fn apply_validate_extension(
    config: &mut Map<String, Value>,
    validate_ext: Value,
) -> Result<(), ExtractError> {
    let Value::Object(map) = validate_ext else {
        return Ok(());
    };
    reject_unknown_validate_keys(&map, "x-ferrum-validate", X_FERRUM_VALIDATE_KEYS)?;
    for (key, value) in map {
        match key.as_str() {
            "mode" => {
                config.insert("enforcement_mode".to_string(), value);
            }
            "request" => {
                apply_validate_side_extension(config, "request", value)?;
            }
            "response" => {
                apply_validate_side_extension(config, "response", value)?;
            }
            "bypass" => {
                validate_openapi_validator_bypass("x-ferrum-validate", &value)?;
                config.insert(key, value);
            }
            // Enumerated above; every remaining key is a plugin config field
            // that carries the same name.
            _ => {
                config.insert(key, value);
            }
        }
    }
    Ok(())
}

fn apply_validate_side_extension(
    config: &mut Map<String, Value>,
    side: &'static str,
    value: Value,
) -> Result<(), ExtractError> {
    let Value::Object(map) = value else {
        return Err(ExtractError::MalformedExtension {
            which: "x-ferrum-validate",
            error: format!("'{side}' must be an object"),
        });
    };
    reject_unknown_validate_keys(
        &map,
        &format!("x-ferrum-validate.{side}"),
        X_FERRUM_VALIDATE_SIDE_KEYS,
    )?;
    for (key, value) in map {
        match key.as_str() {
            "enabled" => {
                config.insert(format!("validate_{side}"), value);
            }
            "content_types" => {
                config.insert(format!("{side}_content_types"), value);
            }
            other => {
                return Err(ExtractError::MalformedExtension {
                    which: "x-ferrum-validate",
                    error: format!("unknown configuration key(s): '{side}.{other}'"),
                });
            }
        }
    }
    Ok(())
}

fn validate_openapi_validator_bypass(
    which: &'static str,
    value: &Value,
) -> Result<(), ExtractError> {
    let object = value
        .as_object()
        .ok_or_else(|| ExtractError::MalformedExtension {
            which,
            error: "openapi_validator bypass config must be an object".to_string(),
        })?;
    crate::util::unknown_keys::reject_unknown_keys(
        object,
        &format!("{which}.bypass"),
        OPENAPI_VALIDATOR_BYPASS_KEYS,
        "",
    )
    .map_err(|error| ExtractError::MalformedExtension { which, error })?;
    for key in ["paths", "methods", "consumers"] {
        if let Some(value) = object.get(key)
            && !value.is_array()
        {
            return Err(ExtractError::MalformedExtension {
                which,
                error: format!("openapi_validator bypass.{key} must be an array"),
            });
        }
    }
    if let Some(value) = object.get("header_present")
        && !value.is_object()
    {
        return Err(ExtractError::MalformedExtension {
            which,
            error: "openapi_validator bypass.header_present must be an object".to_string(),
        });
    }
    Ok(())
}

fn merge_openapi_validator_config(
    auto_config: Value,
    operator_config: &Value,
) -> Result<Value, ExtractError> {
    let mut base =
        auto_config
            .as_object()
            .cloned()
            .ok_or_else(|| ExtractError::MalformedExtension {
                which: "x-ferrum-validate",
                error: "generated openapi_validator config was not an object".to_string(),
            })?;
    let operator = operator_config
        .as_object()
        .ok_or_else(|| ExtractError::MalformedExtension {
            which: "x-ferrum-plugins",
            error: "openapi_validator config must be an object".to_string(),
        })?;
    for (key, value) in operator {
        match key.as_str() {
            "operations" => {}
            "bypass" => merge_bypass_config(&mut base, value)?,
            _ => {
                base.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(Value::Object(base))
}

fn merge_bypass_config(
    base: &mut Map<String, Value>,
    operator_bypass: &Value,
) -> Result<(), ExtractError> {
    validate_openapi_validator_bypass("x-ferrum-plugins", operator_bypass)?;
    let operator = operator_bypass
        .as_object()
        .ok_or_else(|| ExtractError::MalformedExtension {
            which: "x-ferrum-plugins",
            error: "openapi_validator bypass config must be an object".to_string(),
        })?;
    let base_bypass = base
        .entry("bypass".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let base_object =
        base_bypass
            .as_object_mut()
            .ok_or_else(|| ExtractError::MalformedExtension {
                which: "x-ferrum-validate",
                error: "generated openapi_validator bypass config was not an object".to_string(),
            })?;
    for (key, value) in operator {
        match key.as_str() {
            "paths" | "methods" | "consumers" => {
                let mut values = match base_object.get(key) {
                    Some(Value::Array(values)) => values.clone(),
                    Some(_) => {
                        return Err(ExtractError::MalformedExtension {
                            which: "x-ferrum-validate",
                            error: format!("openapi_validator bypass.{key} must be an array"),
                        });
                    }
                    None => Vec::new(),
                };
                if let Some(operator_values) = value.as_array() {
                    for candidate in operator_values {
                        if !values.iter().any(|existing| existing == candidate) {
                            values.push(candidate.clone());
                        }
                    }
                    base_object.insert(key.clone(), Value::Array(values));
                } else {
                    return Err(ExtractError::MalformedExtension {
                        which: "x-ferrum-plugins",
                        error: format!("openapi_validator bypass.{key} must be an array"),
                    });
                }
            }
            "header_present" => {
                let mut headers = match base_object.get(key) {
                    Some(Value::Object(headers)) => headers.clone(),
                    Some(_) => {
                        return Err(ExtractError::MalformedExtension {
                            which: "x-ferrum-validate",
                            error: "openapi_validator bypass.header_present must be an object"
                                .to_string(),
                        });
                    }
                    None => Map::new(),
                };
                let Some(operator_headers) = value.as_object() else {
                    return Err(ExtractError::MalformedExtension {
                        which: "x-ferrum-plugins",
                        error: "openapi_validator bypass.header_present must be an object"
                            .to_string(),
                    });
                };
                headers.extend(operator_headers.clone());
                base_object.insert(key.clone(), Value::Object(headers));
            }
            _ => {
                base_object.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(())
}

fn extract_operation_schemas(
    root: &Value,
    version: &str,
    listen_path: Option<&str>,
    document_base: &Url,
    externals: &HashMap<String, LoadedExternalDocument>,
) -> Result<Vec<Value>, ExtractError> {
    // The validator matches the full inbound path. Only literal prefix routes
    // contribute a mount path; exact/regex routes already describe full paths.
    // strip_listen_path affects backend forwarding, not operation matching.
    let literal_listen_prefix = listen_path
        .filter(|path| path.starts_with('/'))
        .unwrap_or("");
    let listen_prefix = literal_listen_prefix.trim_end_matches('/');
    let resolver = LocalSchemaResolver::build(root, version, document_base, externals)?;
    let root = resolver.primary_root();
    let Some(paths) = root.get("paths").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    let root_server_bases = if version == "2.0" {
        swagger_base_path_bases(root)?
    } else {
        // Absent root `servers` inherits raw Paths-key matching (no base prefix).
        match openapi_server_bases(root.get("servers"), "servers")? {
            None => vec![SERVER_BASE_ROOT.to_string()],
            Some(bases) => bases,
        }
    };
    let mut operations = Vec::new();
    let mut generated_operation_bytes = 0usize;
    // One reference-resolution account for the whole document. Cycle
    // detection, memoization, and the cumulative node/byte budget are all
    // document-scoped, so a hostile document cannot reset any of them by
    // spreading expansion across many paths, operations, or media types
    // (GHSA-8jc7-c52g-85xr).
    let mut resolution_state = ResolutionState::new();
    // Draft selection is emitted once on the top-level openapi_validator config
    // (`schema_draft`). Runtime compiles every operation with that selector;
    // per-operation copies are not part of the published Admin schema.
    for (path_template, path_item) in paths {
        // Resolve Path Item `$ref` (including `components.pathItems` and chained
        // local refs) before looking up HTTP method keys. Without this step,
        // referenced operations never enter the generated validator table.
        // Sibling Path Item fields (including `servers`) overlay the referenced
        // object, so effective servers on resolved Path Items remain correct.
        let resolved_path_item = resolve_path_item(
            resolver.primary_root(),
            path_item,
            path_template,
            MAX_SCHEMA_REF_DEPTH,
            resolver.document_base(),
            &resolver,
            &mut resolution_state,
        )?;
        let Some(path_object) = resolved_path_item.as_object() else {
            continue;
        };
        let path_item_bases = if version == "2.0" {
            None
        } else {
            openapi_server_bases(
                path_object.get("servers"),
                &format!("paths.{path_template}.servers"),
            )?
        };
        for method in HTTP_METHODS {
            let Some(operation) = path_object.get(*method).and_then(Value::as_object) else {
                continue;
            };
            let mut operation_budget = GeneratedOperationBudget {
                remaining_bytes: MAX_OPENAPI_VALIDATOR_CONFIG_SIZE,
            };
            let effective_bases = if version == "2.0" {
                root_server_bases.clone()
            } else {
                // Operation servers > Path Item servers > root servers.
                // Absence at a narrower scope inherits the next outer scope.
                match openapi_server_bases(
                    operation.get("servers"),
                    &format!("paths.{path_template}.{method}.servers"),
                )? {
                    Some(bases) => bases,
                    None => path_item_bases
                        .clone()
                        .unwrap_or_else(|| root_server_bases.clone()),
                }
            };
            let request_body = if version == "2.0" {
                extract_swagger_request_body(
                    resolver.primary_root(),
                    path_object,
                    operation,
                    version,
                    &resolver,
                    &mut operation_budget,
                    &mut resolution_state,
                )?
            } else {
                extract_openapi_request_body(
                    resolver.primary_root(),
                    operation,
                    version,
                    &resolver,
                    &mut operation_budget,
                    &mut resolution_state,
                )?
            };
            let responses = if version == "2.0" {
                extract_swagger_responses(
                    resolver.primary_root(),
                    path_object,
                    operation,
                    version,
                    &resolver,
                    &mut operation_budget,
                    &mut resolution_state,
                )?
            } else {
                extract_openapi_responses(
                    resolver.primary_root(),
                    operation,
                    version,
                    &resolver,
                    &mut operation_budget,
                    &mut resolution_state,
                )?
            };

            // One matcher per distinct effective pathname. Equivalent server
            // pathnames are deduplicated while preserving document order.
            let mut seen_templates = HashSet::new();
            for base in &effective_bases {
                let spec_template = join_server_base_and_path(base, path_template)?;
                // A root operation must match the literal route key. In
                // particular, the router preserves a trailing slash on a listen
                // path even though non-root joins normalize the slash boundary.
                let (effective_template, regex_tail, regex_prefix) =
                    if !listen_prefix.is_empty() && spec_template == "/" {
                        (literal_listen_prefix.to_string(), "", literal_listen_prefix)
                    } else {
                        (
                            format!("{listen_prefix}{spec_template}"),
                            spec_template.as_str(),
                            listen_prefix,
                        )
                    };
                if !seen_templates.insert(effective_template.clone()) {
                    continue;
                }
                let mut entry = Map::new();
                entry.insert(
                    "method".to_string(),
                    Value::String(method.to_ascii_uppercase()),
                );
                entry.insert(
                    "path_template".to_string(),
                    Value::String(effective_template.clone()),
                );
                entry.insert(
                    "path_regex".to_string(),
                    Value::String(path_template_to_regex(regex_tail, regex_prefix)?),
                );
                if let Some((required, content)) = &request_body {
                    entry.insert("request_required".to_string(), Value::Bool(*required));
                    entry.insert(
                        "request_body".to_string(),
                        json!({ "content": content.clone() }),
                    );
                }
                if !responses.is_empty() {
                    entry.insert("responses".to_string(), Value::Object(responses.clone()));
                }
                let entry = Value::Object(entry);
                let entry_bytes = serde_json::to_vec(&entry)
                    .map_err(|error| ExtractError::MalformedExtension {
                        which: "x-ferrum-validate",
                        error: format!(
                            "generated openapi_validator operation could not be serialized: {error}"
                        ),
                    })?
                    .len();
                generated_operation_bytes = generated_operation_bytes
                    .checked_add(entry_bytes)
                    .ok_or_else(|| ExtractError::SchemaTooLarge {
                        location: effective_template.clone(),
                    })?;
                if generated_operation_bytes > MAX_OPENAPI_VALIDATOR_CONFIG_SIZE {
                    return Err(ExtractError::SchemaTooLarge {
                        location: effective_template,
                    });
                }
                operations.push(entry);
            }
        }
    }
    Ok(operations)
}

/// Sentinel / normalized root server pathname: join leaves the Paths key unchanged.
const SERVER_BASE_ROOT: &str = "/";

/// Swagger 2.0 `basePath` → effective server pathname bases for operation matchers.
fn swagger_base_path_bases(root: &Value) -> Result<Vec<String>, ExtractError> {
    match root.get("basePath") {
        None => Ok(vec![SERVER_BASE_ROOT.to_string()]),
        Some(Value::Null) => Ok(vec![SERVER_BASE_ROOT.to_string()]),
        Some(Value::String(base_path)) => {
            if base_path.is_empty() || base_path == "/" {
                return Ok(vec![SERVER_BASE_ROOT.to_string()]);
            }
            if !base_path.starts_with('/') || base_path.contains(['?', '#']) {
                return Err(ExtractError::MalformedExtension {
                    which: "basePath",
                    error: "Swagger basePath must be an absolute path without query or fragment"
                        .to_string(),
                });
            }
            let pathname = server_url_pathname(base_path, "basePath", "basePath")?;
            Ok(vec![pathname])
        }
        Some(_) => Err(ExtractError::MalformedExtension {
            which: "basePath",
            error: "basePath must be a string".to_string(),
        }),
    }
}

/// OpenAPI 3.x `servers` → distinct effective pathnames, or `None` when absent (inherit).
///
/// Explicit empty arrays fail closed. Each server URL contributes only its pathname
/// (authority, scheme, query, and fragment never enter matchers). Server variables
/// are substituted with declared defaults only — enum members are not explored.
fn openapi_server_bases(
    servers: Option<&Value>,
    location: &str,
) -> Result<Option<Vec<String>>, ExtractError> {
    let Some(servers) = servers else {
        return Ok(None);
    };
    let Some(entries) = servers.as_array() else {
        return Err(ExtractError::MalformedExtension {
            which: "servers",
            error: format!("{location} must be an array of Server Objects"),
        });
    };
    if entries.is_empty() {
        return Err(ExtractError::MalformedExtension {
            which: "servers",
            error: format!("{location} must not be an empty array"),
        });
    }

    let mut bases = Vec::new();
    let mut seen = HashSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let Some(object) = entry.as_object() else {
            return Err(ExtractError::MalformedExtension {
                which: "servers",
                error: format!("{location}[{index}] must be a Server Object"),
            });
        };
        let url = object.get("url").and_then(Value::as_str).ok_or_else(|| {
            ExtractError::MalformedExtension {
                which: "servers",
                error: format!("{location}[{index}].url is required and must be a string"),
            }
        })?;
        let substituted = substitute_server_variables(
            url,
            object.get("variables"),
            &format!("{location}[{index}]"),
        )?;
        let pathname =
            server_url_pathname(&substituted, &format!("{location}[{index}].url"), "servers")?;
        if seen.insert(pathname.clone()) {
            bases.push(pathname);
        }
    }
    Ok(Some(bases))
}

/// Substitute `{variable}` placeholders using Server Variable Object defaults.
fn substitute_server_variables(
    url: &str,
    variables: Option<&Value>,
    location: &str,
) -> Result<String, ExtractError> {
    let variable_map = match variables {
        None | Some(Value::Null) => None,
        Some(Value::Object(map)) => Some(map),
        Some(_) => {
            return Err(ExtractError::MalformedExtension {
                which: "servers",
                error: format!("{location}.variables must be an object"),
            });
        }
    };

    let mut out = String::with_capacity(url.len());
    let mut chars = url.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '}' {
            return Err(ExtractError::MalformedExtension {
                which: "servers",
                error: format!("{location}.url has an unmatched closing server-variable brace"),
            });
        }
        if ch != '{' {
            out.push(ch);
            continue;
        }
        let mut name = String::new();
        let mut closed = false;
        for inner in chars.by_ref() {
            if inner == '}' {
                closed = true;
                break;
            }
            if inner == '{' {
                return Err(ExtractError::MalformedExtension {
                    which: "servers",
                    error: format!("{location}.url has nested or malformed server variables"),
                });
            }
            name.push(inner);
        }
        if !closed {
            return Err(ExtractError::MalformedExtension {
                which: "servers",
                error: format!("{location}.url has an unclosed server variable"),
            });
        }
        if name.is_empty() || name.trim() != name {
            return Err(ExtractError::MalformedExtension {
                which: "servers",
                error: format!(
                    "{location}.url has an empty or whitespace-padded server variable name"
                ),
            });
        }
        let Some(vars) = variable_map else {
            return Err(ExtractError::MalformedExtension {
                which: "servers",
                error: format!(
                    "{location}.url references server variable '{name}' but variables are missing"
                ),
            });
        };
        let Some(var_obj) = vars.get(&name).and_then(Value::as_object) else {
            return Err(ExtractError::MalformedExtension {
                which: "servers",
                error: format!("{location}.variables.{name} is required for substitution in url"),
            });
        };
        let Some(default) = var_obj.get("default").and_then(Value::as_str) else {
            return Err(ExtractError::MalformedExtension {
                which: "servers",
                error: format!(
                    "{location}.variables.{name}.default is required and must be a string"
                ),
            });
        };
        if let Some(enum_values) = var_obj.get("enum") {
            let Some(enum_arr) = enum_values.as_array() else {
                return Err(ExtractError::MalformedExtension {
                    which: "servers",
                    error: format!("{location}.variables.{name}.enum must be an array"),
                });
            };
            let allowed: Vec<&str> = enum_arr.iter().filter_map(Value::as_str).collect();
            if allowed.len() != enum_arr.len() {
                return Err(ExtractError::MalformedExtension {
                    which: "servers",
                    error: format!("{location}.variables.{name}.enum entries must be strings"),
                });
            }
            if !allowed.is_empty() && !allowed.contains(&default) {
                return Err(ExtractError::MalformedExtension {
                    which: "servers",
                    error: format!(
                        "{location}.variables.{name}.default must be one of the declared enum values"
                    ),
                });
            }
        }
        if default.contains(['{', '}', '?', '#']) {
            return Err(ExtractError::MalformedExtension {
                which: "servers",
                error: format!(
                    "{location}.variables.{name}.default contains characters that cannot be safely substituted into a server URL"
                ),
            });
        }
        out.push_str(default);
    }
    Ok(out)
}

/// Extract the pathname from a relative or absolute server URL / Swagger basePath.
///
/// Authority, scheme, query, and fragment never enter the matcher. The pathname is
/// kept in URL serialization form (percent escapes stay escaped) so it matches
/// `http::Uri::path()` on the request boundary. Relative references resolve
/// against a synthetic root because uploaded specs have no document URL.
fn server_url_pathname(
    raw: &str,
    location: &str,
    error_surface: &'static str,
) -> Result<String, ExtractError> {
    if raw.is_empty() {
        return Err(ExtractError::MalformedExtension {
            which: error_surface,
            error: format!("{location} must not be empty"),
        });
    }
    if raw.chars().any(|ch| ch.is_control() || ch == '\\') {
        return Err(ExtractError::MalformedExtension {
            which: error_surface,
            error: format!("{location} contains control characters or backslashes"),
        });
    }

    let without_fragment = raw.split_once('#').map(|(head, _)| head).unwrap_or(raw);
    let without_query = without_fragment
        .split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(without_fragment);

    if without_query.split('/').any(is_url_dot_segment) {
        return Err(ExtractError::MalformedExtension {
            which: error_surface,
            error: format!("{location} contains a '.' or '..' path segment"),
        });
    }

    let parsed = if without_query.starts_with("//") {
        Url::parse(&format!("http:{without_query}"))
    } else {
        match Url::parse(without_query) {
            Ok(absolute) => Ok(absolute),
            Err(url::ParseError::RelativeUrlWithoutBase) => {
                Url::parse("http://ferrum.invalid/").and_then(|base| base.join(without_query))
            }
            Err(error) => Err(error),
        }
    }
    .map_err(|error| ExtractError::MalformedExtension {
        which: error_surface,
        error: format!("{location} is not a valid server URL: {error}"),
    })?;
    if parsed.cannot_be_a_base() {
        return Err(ExtractError::MalformedExtension {
            which: error_surface,
            error: format!("{location} does not identify a hierarchical request path"),
        });
    }

    validate_safe_server_pathname(parsed.path(), location, error_surface)
}

fn is_url_dot_segment(segment: &str) -> bool {
    matches!(
        segment.to_ascii_lowercase().as_str(),
        "." | ".." | "%2e" | ".%2e" | "%2e." | "%2e%2e"
    )
}

fn validate_safe_server_pathname(
    pathname: &str,
    location: &str,
    error_surface: &'static str,
) -> Result<String, ExtractError> {
    if pathname.is_empty() || !pathname.starts_with('/') {
        return Err(ExtractError::MalformedExtension {
            which: error_surface,
            error: format!(
                "{location} pathname must be an absolute path starting with '/' (got '{pathname}')"
            ),
        });
    }
    if pathname.chars().any(|ch| ch.is_control() || ch == '\\') {
        return Err(ExtractError::MalformedExtension {
            which: error_surface,
            error: format!("{location} pathname contains control characters or backslashes"),
        });
    }
    if pathname == "/" {
        return Ok(SERVER_BASE_ROOT.to_string());
    }

    // Normalize trailing slash on non-root bases so joins use a single slash boundary.
    let trimmed = pathname.trim_end_matches('/');
    // Dot-segment input is rejected before URL parsing so parser normalization
    // cannot silently change the matcher. Empty segments remain literal and
    // safe because the generated operation regex is fully anchored.
    for segment in trimmed.split('/').skip(1) {
        if segment == "." || segment == ".." {
            return Err(ExtractError::MalformedExtension {
                which: error_surface,
                error: format!(
                    "{location} pathname '{pathname}' contains a '.' or '..' segment and cannot produce a safe absolute request path"
                ),
            });
        }
    }
    Ok(trimmed.to_string())
}

/// Join a server/base pathname with an OpenAPI Paths key.
///
/// Root / no-path servers (`/`) preserve raw Paths-key matching. Otherwise the
/// join uses exactly one slash boundary; the Paths-key root `/` yields the base
/// itself. Query/fragment never appear — Paths keys and bases are path-only.
fn join_server_base_and_path(base: &str, path_key: &str) -> Result<String, ExtractError> {
    if path_key.is_empty() || !path_key.starts_with('/') {
        return Err(ExtractError::MalformedExtension {
            which: "paths",
            error: format!("OpenAPI path key '{path_key}' must be an absolute path"),
        });
    }
    if path_key.contains(['?', '#']) {
        return Err(ExtractError::MalformedExtension {
            which: "paths",
            error: format!("OpenAPI path key '{path_key}' must not contain query or fragment"),
        });
    }
    if base == SERVER_BASE_ROOT {
        return Ok(path_key.to_string());
    }
    if path_key == "/" {
        return Ok(base.to_string());
    }
    Ok(format!("{base}{path_key}"))
}

/// Resolve a Path Item Object that may be supplied through a local `$ref`.
///
/// OpenAPI Path Item Objects (Swagger 2.0 and OpenAPI 3.x) may carry a `$ref`
/// whose target is another Path Item Object in the same document (for example
/// `#/components/pathItems/Pets` on OpenAPI 3.1+). The importer resolves that
/// reference before enumerating HTTP methods.
///
/// Sibling semantics (Swagger 2.0 and OpenAPI 3.x): the OpenAPI Specification
/// leaves conflicts between `$ref` and adjacent Path Item fields undefined.
/// Ferrum applies a deterministic overlay — sibling fields override fields from
/// the referenced Path Item after resolution (same merge used for Reference
/// Objects elsewhere in the importer). Cross-document Path Item refs are only
/// admitted when the effective external-ref policy enables them; otherwise they
/// are rejected as [`ExtractError::UnsupportedExternalRef`]. Unresolved local
/// refs surface as [`ExtractError::SchemaReference`]; cycles and excessive
/// depth as [`ExtractError::SchemaTooDeep`].
fn resolve_path_item(
    root: &Value,
    path_item: &Value,
    location: &str,
    depth: usize,
    current_base: &Url,
    resolver: &LocalSchemaResolver,
    state: &mut ResolutionState,
) -> Result<Value, ExtractError> {
    resolve_refs(
        root,
        path_item,
        location,
        depth,
        current_base,
        resolver,
        ResolveContext::ReferenceObject,
        state,
    )
}

fn extract_openapi_request_body(
    root: &Value,
    operation: &Map<String, Value>,
    version: &str,
    resolver: &LocalSchemaResolver,
    budget: &mut GeneratedOperationBudget,
    state: &mut ResolutionState,
) -> Result<ExtractedRequestBodySchemas, ExtractError> {
    let Some(request_body) = operation.get("requestBody") else {
        return Ok(None);
    };
    let resolved = resolve_refs(
        root,
        request_body,
        "#/paths/requestBody",
        MAX_SCHEMA_REF_DEPTH,
        resolver.document_base(),
        resolver,
        ResolveContext::ReferenceObject,
        state,
    )?;
    let Some(object) = resolved.as_object() else {
        return Ok(None);
    };
    let required = object
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut content_schemas = Map::new();
    if let Some(content) = object.get("content").and_then(Value::as_object) {
        for (media_type, media) in content {
            let Some(media_object) = media.as_object() else {
                continue;
            };
            let Some(schema) = media_object.get("schema") else {
                continue;
            };
            let schema = resolve_refs(
                root,
                schema,
                media_type,
                MAX_SCHEMA_REF_DEPTH,
                resolver.document_base(),
                resolver,
                ResolveContext::Schema,
                state,
            )?;
            let schema = normalize_schema_for_openapi(schema, version, SchemaDirection::Request);
            let encoding = match media_object.get("encoding") {
                None | Some(Value::Null) => None,
                Some(encoding) => Some(normalize_request_body_encoding(
                    root, media_type, encoding, &schema, version, resolver, budget, state,
                )?),
            };
            let media_value = match encoding {
                Some(encoding) => {
                    budget.consume_key(media_type, media_type)?;
                    budget.consume_map_entry("schema", &schema, media_type)?;
                    budget.consume_key("encoding", media_type)?;
                    json!({
                        "schema": schema,
                        "encoding": encoding,
                    })
                }
                None => {
                    budget.consume_map_entry(media_type, &schema, media_type)?;
                    schema
                }
            };
            content_schemas.insert(media_type.clone(), media_value);
        }
    }
    if content_schemas.is_empty() {
        Ok(None)
    } else {
        Ok(Some((required, content_schemas)))
    }
}

/// Preserve and validate OpenAPI Encoding Objects for form-urlencoded / multipart.
///
/// Unsupported styles and media-type combinations fail closed at admission so
/// generated validator config never silently drops serialization metadata.
#[allow(clippy::too_many_arguments)]
fn normalize_request_body_encoding(
    root: &Value,
    media_type: &str,
    encoding: &Value,
    schema: &Value,
    version: &str,
    resolver: &LocalSchemaResolver,
    budget: &mut GeneratedOperationBudget,
    state: &mut ResolutionState,
) -> Result<Value, ExtractError> {
    const HEADER_OBJECT_SCHEMA_KEYS: &[&str] = &[
        "description",
        "required",
        "deprecated",
        "style",
        "explode",
        "schema",
        "example",
        "examples",
    ];
    const HEADER_OBJECT_CONTENT_KEYS: &[&str] =
        &["description", "required", "deprecated", "content"];
    const HEADER_OBJECT_INVALID_KEYS: &[&str] = &["allowEmptyValue", "allowReserved"];
    let base = media_type
        .split(';')
        .next()
        .unwrap_or(media_type)
        .trim()
        .to_ascii_lowercase();
    let object = encoding
        .as_object()
        .ok_or_else(|| ExtractError::MalformedExtension {
            which: "requestBody.content.encoding",
            error: format!("encoding for media type '{media_type}' must be an object"),
        })?;
    if base != "application/x-www-form-urlencoded" && base != "multipart/form-data" {
        return Err(ExtractError::MalformedExtension {
            which: "requestBody.content.encoding",
            error: format!(
                "encoding is only supported for application/x-www-form-urlencoded and multipart/form-data (got '{media_type}')"
            ),
        });
    }
    if object.is_empty() {
        return Ok(Value::Object(Map::new()));
    }

    let mut out = Map::new();
    for (property, value) in object {
        let property_location =
            format!("requestBody.content['{media_type}'].encoding['{property}']");
        budget.consume_key(property, &property_location)?;
        let property_schema = request_body_property_schema(schema, property).ok_or_else(|| {
            ExtractError::MalformedExtension {
                which: "requestBody.content.encoding",
                error: format!(
                    "encoding['{property}'] does not name a request-body schema property"
                ),
            }
        })?;
        let mut property_object =
            value
                .as_object()
                .cloned()
                .ok_or_else(|| ExtractError::MalformedExtension {
                    which: "requestBody.content.encoding",
                    error: format!("encoding['{property}'] must be an object"),
                })?;
        for key in property_object.keys() {
            if !matches!(
                key.as_str(),
                "style" | "explode" | "allowReserved" | "contentType" | "headers"
            ) {
                return Err(ExtractError::MalformedExtension {
                    which: "requestBody.content.encoding",
                    error: format!("encoding['{property}'] contains unsupported field '{key}'"),
                });
            }
        }
        for key in ["style", "explode", "allowReserved", "contentType"] {
            if let Some(value) = property_object.get(key) {
                budget.consume_map_entry(key, value, &property_location)?;
            }
        }

        let style = match property_object.get("style") {
            None => "form",
            Some(Value::String(value)) => value.as_str(),
            Some(_) => {
                return Err(ExtractError::MalformedExtension {
                    which: "requestBody.content.encoding",
                    error: format!("encoding['{property}'].style must be a string"),
                });
            }
        };
        if !matches!(
            style,
            "form" | "spaceDelimited" | "pipeDelimited" | "deepObject"
        ) {
            return Err(ExtractError::MalformedExtension {
                which: "requestBody.content.encoding",
                error: format!(
                    "encoding['{property}'].style '{style}' is unsupported for request bodies"
                ),
            });
        }
        let explode = match property_object.get("explode") {
            None => style == "form",
            Some(Value::Bool(value)) => *value,
            Some(_) => {
                return Err(ExtractError::MalformedExtension {
                    which: "requestBody.content.encoding",
                    error: format!("encoding['{property}'].explode must be a boolean"),
                });
            }
        };
        if let Some(allow_reserved) = property_object.get("allowReserved")
            && !allow_reserved.is_boolean()
        {
            return Err(ExtractError::MalformedExtension {
                which: "requestBody.content.encoding",
                error: format!("encoding['{property}'].allowReserved must be a boolean"),
            });
        }
        match (style, explode) {
            ("form", _) | ("spaceDelimited" | "pipeDelimited", false) | ("deepObject", true) => {}
            ("spaceDelimited" | "pipeDelimited", true) => {
                return Err(ExtractError::MalformedExtension {
                    which: "requestBody.content.encoding",
                    error: format!(
                        "encoding['{property}']: style '{style}' requires explode=false"
                    ),
                });
            }
            ("deepObject", false) => {
                return Err(ExtractError::MalformedExtension {
                    which: "requestBody.content.encoding",
                    error: format!(
                        "encoding['{property}']: style 'deepObject' requires explode=true"
                    ),
                });
            }
            _ => {}
        }

        if style == "deepObject" && !request_body_schema_accepts_object(property_schema, 0) {
            return Err(ExtractError::MalformedExtension {
                which: "requestBody.content.encoding",
                error: format!(
                    "encoding['{property}']: style 'deepObject' requires an object schema property"
                ),
            });
        }
        if matches!(style, "spaceDelimited" | "pipeDelimited")
            && !(request_body_schema_accepts_array(property_schema, 0)
                || request_body_schema_accepts_object(property_schema, 0))
        {
            return Err(ExtractError::MalformedExtension {
                which: "requestBody.content.encoding",
                error: format!(
                    "encoding['{property}']: style '{style}' requires an array or object schema property"
                ),
            });
        }

        if let Some(content_type) = property_object.get("contentType") {
            if base != "multipart/form-data" {
                return Err(ExtractError::MalformedExtension {
                    which: "requestBody.content.encoding",
                    error: format!(
                        "encoding['{property}'].contentType is only valid for multipart/form-data"
                    ),
                });
            }
            let Some(content_type) = content_type.as_str() else {
                return Err(ExtractError::MalformedExtension {
                    which: "requestBody.content.encoding",
                    error: format!("encoding['{property}'].contentType must be a string"),
                });
            };
            if content_type.trim().is_empty() || content_type.len() > 4 * 1024 {
                return Err(ExtractError::MalformedExtension {
                    which: "requestBody.content.encoding",
                    error: format!(
                        "encoding['{property}'].contentType must be non-empty and at most 4096 bytes"
                    ),
                });
            }
        }
        if let Some(headers) = property_object.get("headers") {
            budget.consume_key("headers", &property_location)?;
            if base != "multipart/form-data" {
                return Err(ExtractError::MalformedExtension {
                    which: "requestBody.content.encoding",
                    error: format!(
                        "encoding['{property}'].headers is only valid for multipart/form-data"
                    ),
                });
            }
            let Some(headers) = headers.as_object() else {
                return Err(ExtractError::MalformedExtension {
                    which: "requestBody.content.encoding",
                    error: format!("encoding['{property}'].headers must be an object"),
                });
            };
            if headers.len() > 32 {
                return Err(ExtractError::MalformedExtension {
                    which: "requestBody.content.encoding",
                    error: format!("encoding['{property}'].headers must not exceed 32 entries"),
                });
            }
            let mut normalized_headers = Map::new();
            let mut seen_header_names = HashSet::new();
            for (header_name, header_value) in headers {
                let name = header_name.trim().to_ascii_lowercase();
                if http::header::HeaderName::from_bytes(name.as_bytes()).is_err()
                    || matches!(
                        name.as_str(),
                        "content-type" | "content-disposition" | "content-transfer-encoding"
                    )
                {
                    return Err(ExtractError::MalformedExtension {
                        which: "requestBody.content.encoding",
                        error: format!(
                            "encoding['{property}'].headers contains invalid or reserved header '{header_name}'"
                        ),
                    });
                }
                if !seen_header_names.insert(name) {
                    return Err(ExtractError::MalformedExtension {
                        which: "requestBody.content.encoding",
                        error: format!(
                            "requestBody.content['{media_type}'].encoding['{property}'].headers contains duplicate header name '{header_name}'"
                        ),
                    });
                }
                let location = format!(
                    "requestBody.content['{media_type}'].encoding['{property}'].headers['{header_name}']"
                );
                let resolved_header = resolve_refs(
                    root,
                    header_value,
                    &location,
                    MAX_SCHEMA_REF_DEPTH,
                    resolver.document_base(),
                    resolver,
                    ResolveContext::ReferenceObject,
                    state,
                )?;
                let Some(header_object) = resolved_header.as_object() else {
                    return Err(ExtractError::MalformedExtension {
                        which: "requestBody.content.encoding",
                        error: format!(
                            "encoding['{property}'].headers['{header_name}'] must be a Header Object"
                        ),
                    });
                };
                let has_schema = header_object.contains_key("schema");
                let has_content = header_object.contains_key("content");
                if has_schema && has_content {
                    return Err(ExtractError::MalformedExtension {
                        which: "requestBody.content.encoding",
                        error: format!(
                            "encoding['{property}'].headers['{header_name}'] must not declare both schema and content"
                        ),
                    });
                }
                if !has_schema && !has_content {
                    return Err(ExtractError::MalformedExtension {
                        which: "requestBody.content.encoding",
                        error: format!(
                            "encoding['{property}'].headers['{header_name}'] must contain schema or content"
                        ),
                    });
                }
                for key in HEADER_OBJECT_INVALID_KEYS {
                    if header_object.contains_key(*key) {
                        return Err(ExtractError::MalformedExtension {
                            which: "requestBody.content.encoding",
                            error: format!(
                                "encoding['{property}'].headers['{header_name}'].{key} is not valid for Header Objects"
                            ),
                        });
                    }
                }
                if has_content {
                    for key in ["style", "explode", "example", "examples", "schema"] {
                        if header_object.contains_key(key) {
                            return Err(ExtractError::MalformedExtension {
                                which: "requestBody.content.encoding",
                                error: format!(
                                    "encoding['{property}'].headers['{header_name}'].{key} is a schema-form Header Object field and is not valid with content"
                                ),
                            });
                        }
                    }
                }
                let allowed_keys = if has_content {
                    HEADER_OBJECT_CONTENT_KEYS
                } else {
                    HEADER_OBJECT_SCHEMA_KEYS
                };
                for key in header_object.keys() {
                    if !allowed_keys.contains(&key.as_str()) {
                        return Err(ExtractError::MalformedExtension {
                            which: "requestBody.content.encoding",
                            error: format!(
                                "encoding['{property}'].headers['{header_name}'] contains unsupported field '{key}'"
                            ),
                        });
                    }
                }
                if let Some(description) = header_object.get("description")
                    && !description.is_null()
                    && !description.is_string()
                {
                    return Err(ExtractError::MalformedExtension {
                        which: "requestBody.content.encoding",
                        error: format!(
                            "encoding['{property}'].headers['{header_name}'].description must be a string"
                        ),
                    });
                }
                if let Some(deprecated) = header_object.get("deprecated")
                    && !deprecated.is_boolean()
                {
                    return Err(ExtractError::MalformedExtension {
                        which: "requestBody.content.encoding",
                        error: format!(
                            "encoding['{property}'].headers['{header_name}'].deprecated must be a boolean"
                        ),
                    });
                }
                if let Some(required) = header_object.get("required")
                    && !required.is_boolean()
                {
                    return Err(ExtractError::MalformedExtension {
                        which: "requestBody.content.encoding",
                        error: format!(
                            "encoding['{property}'].headers['{header_name}'].required must be a boolean"
                        ),
                    });
                }
                if !has_content {
                    if let Some(style) = header_object.get("style")
                        && style.as_str() != Some("simple")
                    {
                        return Err(ExtractError::MalformedExtension {
                            which: "requestBody.content.encoding",
                            error: format!(
                                "encoding['{property}'].headers['{header_name}'].style must be 'simple'"
                            ),
                        });
                    }
                    if let Some(explode) = header_object.get("explode")
                        && !explode.is_boolean()
                    {
                        return Err(ExtractError::MalformedExtension {
                            which: "requestBody.content.encoding",
                            error: format!(
                                "encoding['{property}'].headers['{header_name}'].explode must be a boolean"
                            ),
                        });
                    }
                    if let Some(examples) = header_object.get("examples")
                        && !examples.is_object()
                    {
                        return Err(ExtractError::MalformedExtension {
                            which: "requestBody.content.encoding",
                            error: format!(
                                "encoding['{property}'].headers['{header_name}'].examples must be an object"
                            ),
                        });
                    }
                }
                let mut normalized_header = header_object.clone();
                if has_content {
                    let content_object = header_object
                        .get("content")
                        .and_then(Value::as_object)
                        .ok_or_else(|| ExtractError::MalformedExtension {
                            which: "requestBody.content.encoding",
                            error: format!(
                                "encoding['{property}'].headers['{header_name}'].content must be an object"
                            ),
                        })?;
                    if content_object.len() != 1 {
                        return Err(ExtractError::MalformedExtension {
                            which: "requestBody.content.encoding",
                            error: format!(
                                "encoding['{property}'].headers['{header_name}'].content must contain exactly one media type"
                            ),
                        });
                    }
                    let (content_media_type, media_value) = content_object.iter().next().ok_or_else(
                        || ExtractError::MalformedExtension {
                            which: "requestBody.content.encoding",
                            error: format!(
                                "encoding['{property}'].headers['{header_name}'].content must contain exactly one media type"
                            ),
                        },
                    )?;
                    let content_media_location =
                        format!("{location}.content['{content_media_type}']");
                    validate_header_content_media_type_key(
                        content_media_type,
                        property,
                        header_name,
                    )?;
                    let content_media_base = content_media_type
                        .split(';')
                        .next()
                        .unwrap_or(content_media_type)
                        .trim()
                        .to_ascii_lowercase();
                    if content_media_base == "multipart/form-data" {
                        return Err(ExtractError::MalformedExtension {
                            which: "requestBody.content.encoding",
                            error: format!(
                                "encoding['{property}'].headers['{header_name}'].content['{content_media_type}'] is not a supported header content media type"
                            ),
                        });
                    }
                    budget.consume_key(content_media_type, &content_media_location)?;
                    let media_object =
                        media_value
                            .as_object()
                            .ok_or_else(|| ExtractError::MalformedExtension {
                                which: "requestBody.content.encoding",
                                error: format!(
                                    "encoding['{property}'].headers['{header_name}'].content['{content_media_type}'] must be a Media Type Object"
                                ),
                            })?;
                    for key in media_object.keys() {
                        if !matches!(key.as_str(), "schema" | "example" | "examples") {
                            return Err(ExtractError::MalformedExtension {
                                which: "requestBody.content.encoding",
                                error: format!(
                                    "encoding['{property}'].headers['{header_name}'].content['{content_media_type}'] contains unsupported field '{key}'"
                                ),
                            });
                        }
                    }
                    let Some(header_schema) = media_object.get("schema") else {
                        return Err(ExtractError::MalformedExtension {
                            which: "requestBody.content.encoding",
                            error: format!(
                                "encoding['{property}'].headers['{header_name}'].content['{content_media_type}'] must contain schema"
                            ),
                        });
                    };
                    if let Some(examples) = media_object.get("examples")
                        && !examples.is_object()
                    {
                        return Err(ExtractError::MalformedExtension {
                            which: "requestBody.content.encoding",
                            error: format!(
                                "encoding['{property}'].headers['{header_name}'].content['{content_media_type}'].examples must be an object"
                            ),
                        });
                    }
                    if media_object.contains_key("example") && media_object.contains_key("examples")
                    {
                        return Err(ExtractError::MalformedExtension {
                            which: "requestBody.content.encoding",
                            error: format!(
                                "encoding['{property}'].headers['{header_name}'].content['{content_media_type}'].example and .examples are mutually exclusive"
                            ),
                        });
                    }
                    let resolved_schema = resolve_refs(
                        root,
                        header_schema,
                        &format!("{content_media_location}.schema"),
                        MAX_SCHEMA_REF_DEPTH,
                        resolver.document_base(),
                        resolver,
                        ResolveContext::Schema,
                        state,
                    )?;
                    let mut normalized_media = media_object.clone();
                    let normalized_schema = normalize_schema_for_openapi(
                        resolved_schema,
                        version,
                        SchemaDirection::Request,
                    );
                    budget.consume_map_entry(
                        "schema",
                        &normalized_schema,
                        &content_media_location,
                    )?;
                    normalized_media.insert("schema".to_string(), normalized_schema);
                    let mut normalized_content = Map::new();
                    normalized_content
                        .insert(content_media_type.clone(), Value::Object(normalized_media));
                    normalized_header.remove("schema");
                    normalized_header
                        .insert("content".to_string(), Value::Object(normalized_content));
                } else {
                    let header_schema =
                        header_object
                            .get("schema")
                            .ok_or_else(|| ExtractError::MalformedExtension {
                                which: "requestBody.content.encoding",
                                error: format!(
                                    "encoding['{property}'].headers['{header_name}'] must contain schema"
                                ),
                            })?;
                    let resolved_schema = resolve_refs(
                        root,
                        header_schema,
                        &format!("{location}.schema"),
                        MAX_SCHEMA_REF_DEPTH,
                        resolver.document_base(),
                        resolver,
                        ResolveContext::Schema,
                        state,
                    )?;
                    normalized_header.remove("content");
                    normalized_header.insert(
                        "schema".to_string(),
                        normalize_schema_for_openapi(
                            resolved_schema,
                            version,
                            SchemaDirection::Request,
                        ),
                    );
                }
                let normalized_header = Value::Object(normalized_header);
                budget.consume_map_entry(header_name, &normalized_header, &location)?;
                normalized_headers.insert(header_name.clone(), normalized_header);
            }
            property_object.insert("headers".to_string(), Value::Object(normalized_headers));
        }

        out.insert(property.clone(), Value::Object(property_object));
    }
    Ok(Value::Object(out))
}

/// Fail closed on Header Object `content` map keys using the same concrete
/// RFC 9110 media-type + HTTP header-value gate as plugin admission. Validates
/// the full key (including parameter grammar) so malformed or control-bearing
/// suffixes cannot be silently discarded after a `;` split.
fn validate_header_content_media_type_key(
    value: &str,
    property: &str,
    header_name: &str,
) -> Result<(), ExtractError> {
    let path = format!("encoding['{property}'].headers['{header_name}'].content['{value}']");
    if value.parse::<http::HeaderValue>().is_err() {
        return Err(ExtractError::MalformedExtension {
            which: "requestBody.content.encoding",
            error: format!("{path} must be a valid HTTP header value"),
        });
    }
    if !is_concrete_http_media_type(value) {
        return Err(ExtractError::MalformedExtension {
            which: "requestBody.content.encoding",
            error: format!("{path} must be a concrete media type"),
        });
    }
    Ok(())
}

fn request_body_property_schema<'a>(schema: &'a Value, property: &str) -> Option<&'a Value> {
    schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(property))
        .or_else(|| {
            ["allOf", "oneOf", "anyOf"].into_iter().find_map(|keyword| {
                schema
                    .get(keyword)
                    .and_then(Value::as_array)
                    .and_then(|branches| {
                        branches
                            .iter()
                            .find_map(|branch| request_body_property_schema(branch, property))
                    })
            })
        })
}

fn request_body_schema_accepts_object(schema: &Value, depth: usize) -> bool {
    if depth > 32 {
        return false;
    }
    if schema.get("type").and_then(Value::as_str) == Some("object")
        || schema
            .get("type")
            .and_then(Value::as_array)
            .is_some_and(|types| types.iter().any(|value| value.as_str() == Some("object")))
        || schema.get("properties").is_some()
    {
        return true;
    }
    ["allOf", "oneOf", "anyOf"].into_iter().any(|keyword| {
        schema
            .get(keyword)
            .and_then(Value::as_array)
            .is_some_and(|branches| {
                branches
                    .iter()
                    .any(|branch| request_body_schema_accepts_object(branch, depth + 1))
            })
    })
}

fn request_body_schema_accepts_array(schema: &Value, depth: usize) -> bool {
    if depth > 32 {
        return false;
    }
    if schema.get("type").and_then(Value::as_str) == Some("array")
        || schema
            .get("type")
            .and_then(Value::as_array)
            .is_some_and(|types| types.iter().any(|value| value.as_str() == Some("array")))
        || schema.get("items").is_some()
    {
        return true;
    }
    ["allOf", "oneOf", "anyOf"].into_iter().any(|keyword| {
        schema
            .get(keyword)
            .and_then(Value::as_array)
            .is_some_and(|branches| {
                branches
                    .iter()
                    .any(|branch| request_body_schema_accepts_array(branch, depth + 1))
            })
    })
}

fn extract_openapi_responses(
    root: &Value,
    operation: &Map<String, Value>,
    version: &str,
    resolver: &LocalSchemaResolver,
    budget: &mut GeneratedOperationBudget,
    state: &mut ResolutionState,
) -> Result<Map<String, Value>, ExtractError> {
    let mut out = Map::new();
    let Some(responses) = operation.get("responses").and_then(Value::as_object) else {
        return Ok(out);
    };
    for (status, response) in responses {
        budget.consume_key(status, status)?;
        let resolved = resolve_refs(
            root,
            response,
            status,
            MAX_SCHEMA_REF_DEPTH,
            resolver.document_base(),
            resolver,
            ResolveContext::ReferenceObject,
            state,
        )?;
        let Some(response_object) = resolved.as_object() else {
            continue;
        };
        let mut content_schemas = Map::new();
        if let Some(content) = response_object.get("content").and_then(Value::as_object) {
            for (media_type, media) in content {
                if let Some(schema) = media.get("schema") {
                    let schema = resolve_refs(
                        root,
                        schema,
                        media_type,
                        MAX_SCHEMA_REF_DEPTH,
                        resolver.document_base(),
                        resolver,
                        ResolveContext::Schema,
                        state,
                    )?;
                    let schema =
                        normalize_schema_for_openapi(schema, version, SchemaDirection::Response);
                    budget.consume_map_entry(media_type, &schema, status)?;
                    content_schemas.insert(media_type.clone(), schema);
                }
            }
        }
        // Emit declared statuses even when they carry no schema-bearing
        // content. An exact status declaration must preclude `4XX` / `default`
        // fallback at runtime, which the validator can only honor if the
        // declaration survives generation (GHSA-cjqx-p554-5rx9).
        out.insert(status.clone(), Value::Object(content_schemas));
    }
    Ok(out)
}

fn extract_swagger_request_body(
    root: &Value,
    path_item: &Map<String, Value>,
    operation: &Map<String, Value>,
    version: &str,
    resolver: &LocalSchemaResolver,
    budget: &mut GeneratedOperationBudget,
    state: &mut ResolutionState,
) -> Result<ExtractedRequestBodySchemas, ExtractError> {
    let parameters = operation
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            path_item
                .get("parameters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        );
    for parameter in parameters {
        let resolved = resolve_refs(
            root,
            parameter,
            "#/paths/parameters",
            MAX_SCHEMA_REF_DEPTH,
            resolver.document_base(),
            resolver,
            ResolveContext::ReferenceObject,
            state,
        )?;
        let Some(parameter_object) = resolved.as_object() else {
            continue;
        };
        if parameter_object.get("in").and_then(Value::as_str) != Some("body") {
            continue;
        }
        let Some(schema) = parameter_object.get("schema") else {
            continue;
        };
        let schema = resolve_refs(
            root,
            schema,
            "body",
            MAX_SCHEMA_REF_DEPTH,
            resolver.document_base(),
            resolver,
            ResolveContext::Schema,
            state,
        )?;
        let schema = normalize_schema_for_openapi(schema, version, SchemaDirection::Request);
        let required = parameter_object
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mut content = Map::new();
        for media_type in swagger_media_types(root, path_item, operation, "consumes") {
            budget.consume_map_entry(&media_type, &schema, "body")?;
            content.insert(media_type, schema.clone());
        }
        return Ok(Some((required, content)));
    }
    Ok(None)
}

fn extract_swagger_responses(
    root: &Value,
    path_item: &Map<String, Value>,
    operation: &Map<String, Value>,
    version: &str,
    resolver: &LocalSchemaResolver,
    budget: &mut GeneratedOperationBudget,
    state: &mut ResolutionState,
) -> Result<Map<String, Value>, ExtractError> {
    let mut out = Map::new();
    let Some(responses) = operation.get("responses").and_then(Value::as_object) else {
        return Ok(out);
    };
    let produces = swagger_media_types(root, path_item, operation, "produces");
    for (status, response) in responses {
        budget.consume_key(status, status)?;
        let resolved = resolve_refs(
            root,
            response,
            status,
            MAX_SCHEMA_REF_DEPTH,
            resolver.document_base(),
            resolver,
            ResolveContext::ReferenceObject,
            state,
        )?;
        let Some(response_object) = resolved.as_object() else {
            continue;
        };
        let mut content = Map::new();
        // As above: a declared status with no `schema` still occupies its slot
        // so it cannot fall through to a wildcard or `default` response.
        if let Some(schema) = response_object.get("schema") {
            let schema = resolve_refs(
                root,
                schema,
                status,
                MAX_SCHEMA_REF_DEPTH,
                resolver.document_base(),
                resolver,
                ResolveContext::Schema,
                state,
            )?;
            let schema = normalize_schema_for_openapi(schema, version, SchemaDirection::Response);
            for media_type in &produces {
                budget.consume_map_entry(media_type, &schema, status)?;
                content.insert(media_type.clone(), schema.clone());
            }
        }
        out.insert(status.clone(), Value::Object(content));
    }
    Ok(out)
}

fn swagger_media_types(
    root: &Value,
    path_item: &Map<String, Value>,
    operation: &Map<String, Value>,
    key: &'static str,
) -> Vec<String> {
    operation
        .get(key)
        .or_else(|| path_item.get(key))
        .or_else(|| root.get(key))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .filter(|values: &Vec<String>| !values.is_empty())
        .unwrap_or_else(|| vec!["application/json".to_string()])
}

const MAX_SCHEMA_REF_DEPTH: usize = 32;
/// Maximum number of values materialized by one schema/reference expansion.
///
/// A shallow schema can otherwise use repeated local `$ref` branches to grow
/// exponentially before the generated-config byte limit is checked.
const MAX_RESOLVED_SCHEMA_NODES: usize = 500_000;
/// Cumulative cap on values materialized by *every* reference expansion
/// performed while importing one document (GHSA-8jc7-c52g-85xr).
///
/// The per-expansion cap above bounds a single schema. It does not bound a
/// document that repeats a bounded-but-large expansion across many paths,
/// operations, media types, or response statuses: each of those used to start
/// from a fresh budget, so total materialization scaled with the number of
/// expansion sites rather than with any fixed ceiling. One document-scoped
/// account is threaded through the whole extraction so the importer's peak
/// materialization is a constant, independent of document shape.
///
/// Sized at four times the single-expansion cap. Byte accounting below is the
/// binding constraint on memory; this is the secondary structural guard, set
/// with enough headroom that a large real document (hundreds of operations
/// sharing sizable schemas) still imports — the largest public specs
/// materialize well under 100k values in total.
const MAX_TOTAL_RESOLVED_SCHEMA_NODES: usize = 4 * MAX_RESOLVED_SCHEMA_NODES;
/// Cumulative byte cap companion to [`MAX_TOTAL_RESOLVED_SCHEMA_NODES`].
///
/// Bytes are charged against the JSON-serialized representation, so this is a
/// direct ceiling on how much attacker-influenced memory one import may
/// materialize before it is rejected. The expansion memo retains at most one
/// copy of each distinct expansion it caches, so an import's peak retained
/// resolution memory is at most twice this figure.
const MAX_TOTAL_RESOLVED_SCHEMA_BYTES: usize = 2 * MAX_OPENAPI_VALIDATOR_CONFIG_SIZE;
const MAX_SCHEMA_INDEX_DEPTH: usize = 64;
/// Path Item recursion grows several YAML/JSON container levels per callback.
/// Keep its explicit resolver budget below the parsers' own recursion ceiling
/// so hostile callback chains are rejected deterministically as schema depth,
/// while ordinary Schema Object indexing retains its larger independent cap.
const MAX_PATH_ITEM_INDEX_DEPTH: usize = 24;
/// Synthetic document base for local-only URI resolution when no operator
/// `document_base` is configured. Never fetched.
///
/// Kept as the extractor-side name for [`super::external_refs::DEFAULT_DOCUMENT_BASE`];
/// [`EffectiveExternalRefPolicy::document_base`] already defaults to this value.
#[allow(dead_code)]
const LOCAL_SCHEMA_DOCUMENT_BASE: &str = super::external_refs::DEFAULT_DOCUMENT_BASE;
type ExtractedRequestBodySchemas = Option<(bool, Map<String, Value>)>;

/// Incremental cap for all materialized request/response entries in one
/// generated operation.
///
/// Each individual `$ref` expansion has its own resolver budget, but a hostile
/// operation can repeat the same bounded expansion under many media types or
/// statuses. Charge every emitted map entry before retaining it so those
/// individually valid expansions cannot accumulate far beyond the generated
/// config ceiling before the final serialized-entry check runs.
struct GeneratedOperationBudget {
    remaining_bytes: usize,
}

impl GeneratedOperationBudget {
    fn consume_key(&mut self, key: &str, location: &str) -> Result<(), ExtractError> {
        // Quoted key plus `:` / `,` structural bytes. The trailing comma is a
        // one-byte overestimate for the final entry and therefore fail-safe.
        self.consume_bytes(json_string_serialized_len(key).saturating_add(2), location)
    }

    fn consume_map_entry(
        &mut self,
        key: &str,
        value: &Value,
        location: &str,
    ) -> Result<(), ExtractError> {
        let (_, value_bytes) = opaque_value_weight(value);
        self.consume_bytes(
            json_string_serialized_len(key)
                .saturating_add(2)
                .saturating_add(value_bytes),
            location,
        )
    }

    fn consume_bytes(&mut self, bytes: usize, location: &str) -> Result<(), ExtractError> {
        let Some(remaining) = self.remaining_bytes.checked_sub(bytes) else {
            return Err(ExtractError::SchemaTooLarge {
                location: location.to_string(),
            });
        };
        self.remaining_bytes = remaining;
        Ok(())
    }
}

/// Indexes schema resources and plain-name anchors for `$ref` resolution across
/// the primary OpenAPI document and any admission-time external documents.
///
/// Only OpenAPI Schema Object entry points and nested JSON Schema subschema
/// positions are indexed. Non-schema OpenAPI data (extensions, plugin config,
/// examples) and schema annotation payloads (`default` / `examples` / `const` /
/// `enum`) are ignored so `$id` / `id` / `$anchor` there cannot bind fragments.
///
/// Cross-document / network `$ref`s are admitted only when the effective
/// external-ref policy enabled loading and the target URI is present in this
/// resolver's document set. A `$ref` whose absolute URI (without fragment) is
/// not an indexed resource is rejected as [`ExtractError::UnsupportedExternalRef`].
struct LocalSchemaResolver {
    /// Index 0 is the primary submitted document; further entries are externals.
    documents: Vec<ResolverDocument>,
    /// Primary document base (`policy.document_base` or the local synthetic base).
    document_base: Url,
    /// Absolute resource URI → (anchor name → JSON Pointer within that resource's document).
    anchors: HashMap<String, HashMap<String, String>>,
    /// Resource roots for longest-prefix base lookup without reparsing URLs.
    /// Membership of a resource URI is defined by this list's `key` values.
    resource_roots: Vec<SchemaResourceRoot>,
    /// OpenAPI 3.1+ uses `$anchor`; Swagger 2.0 / OAS 3.0 use Draft-7 `$id`/`id` fragments.
    use_dollar_anchor: bool,
    /// OpenAPI 3.1+ Schema Objects inherit JSON Schema 2020-12 semantics, where
    /// `$ref` is an applicator and adjacent keywords are independent assertions
    /// that must *also* hold. Swagger 2.0 / OAS 3.0 Schema Objects use JSON
    /// Reference semantics, where adjacent keywords carry no meaning at all.
    /// Either way an adjacent keyword may never replace the referenced
    /// assertion (GHSA-rf4j-rhmf-8whm).
    schema_object_ref_siblings: bool,
    /// Document currently being indexed (used by `register_resource_root`).
    indexing_doc: usize,
}

struct ResolverDocument {
    root: Value,
    base: Url,
    /// Admitted request URIs that redirected to `base`.
    aliases: Vec<String>,
    /// True when the document root itself is a Schema Object resource (schema-only files).
    root_is_schema: bool,
}

struct SchemaResourceRoot {
    doc_index: usize,
    pointer: String,
    key: String,
    base: Url,
}

/// Result of resolving a `$ref` against the multi-document resolver.
struct ResolvedRef<'a> {
    target: &'a Value,
    target_base: Url,
    /// Root of the document that owns `target` (for nested ref expansion).
    document_root: &'a Value,
}

impl LocalSchemaResolver {
    fn build(
        root: &Value,
        version: &str,
        document_base: &Url,
        externals: &HashMap<String, LoadedExternalDocument>,
    ) -> Result<Self, ExtractError> {
        let mut documents = Vec::with_capacity(1 + externals.len());
        documents.push(ResolverDocument {
            root: root.clone(),
            base: document_base.clone(),
            aliases: Vec::new(),
            root_is_schema: false,
        });
        let mut external_list: Vec<_> = externals.iter().collect();
        external_list.sort_unstable_by(|(left_key, left), (right_key, right)| {
            resource_uri_key(&left.canonical_uri)
                .cmp(&resource_uri_key(&right.canonical_uri))
                .then_with(|| left_key.cmp(right_key))
        });
        for (requested_key, ext) in external_list {
            let mut base = ext.canonical_uri.clone();
            base.set_fragment(None);
            let canonical_key = resource_uri_key(&base);
            if let Some(existing) = documents
                .iter_mut()
                .skip(1)
                .find(|document| resource_uri_key(&document.base) == canonical_key)
            {
                if existing.root != ext.root {
                    return Err(schema_reference_error(
                        "external $ref aliases resolved to inconsistent document content"
                            .to_string(),
                    ));
                }
                if requested_key != &canonical_key
                    && !existing.aliases.iter().any(|alias| alias == requested_key)
                {
                    existing.aliases.push(requested_key.clone());
                }
                continue;
            }
            let root_is_schema = is_schema_only_document(&ext.root);
            documents.push(ResolverDocument {
                root: ext.root.clone(),
                base,
                aliases: if requested_key == &canonical_key {
                    Vec::new()
                } else {
                    vec![requested_key.clone()]
                },
                root_is_schema,
            });
        }

        let use_dollar_anchor = version != "2.0" && !version.starts_with("3.0.");
        let mut resolver = Self {
            documents,
            document_base: document_base.clone(),
            anchors: HashMap::new(),
            resource_roots: Vec::new(),
            use_dollar_anchor,
            schema_object_ref_siblings: use_dollar_anchor,
            indexing_doc: 0,
        };

        for doc_index in 0..resolver.documents.len() {
            resolver.index_owned_document(doc_index)?;
        }
        // Longest JSON Pointer prefix wins when locating a node's resource
        // (filtered by doc_index at lookup time).
        resolver
            .resource_roots
            .sort_by_key(|root| std::cmp::Reverse(root.pointer.len()));
        Ok(resolver)
    }

    fn document_base(&self) -> &Url {
        &self.document_base
    }

    fn primary_root(&self) -> &Value {
        &self.documents[0].root
    }

    fn index_owned_document(&mut self, doc_index: usize) -> Result<(), ExtractError> {
        self.indexing_doc = doc_index;
        let base = self.documents[doc_index].base.clone();
        let aliases = self.documents[doc_index].aliases.clone();
        let root_is_schema = self.documents[doc_index].root_is_schema;
        let document_key = resource_uri_key(&base);
        self.register_document_root(doc_index, document_key, &base)?;
        for alias in aliases {
            self.register_document_root(doc_index, alias, &base)?;
        }

        // Temporarily take the root so indexing can borrow `&mut self` while
        // walking the owned Value.
        let root = std::mem::replace(&mut self.documents[doc_index].root, Value::Null);
        let result = if root_is_schema {
            self.index_schema(&root, &base, "", MAX_SCHEMA_INDEX_DEPTH)
        } else {
            self.index_openapi_schemas(&root, &base, MAX_SCHEMA_INDEX_DEPTH)
        };
        self.documents[doc_index].root = root;
        result
    }

    fn register_document_root(
        &mut self,
        doc_index: usize,
        key: String,
        base: &Url,
    ) -> Result<(), ExtractError> {
        if let Some(existing) = self.resource_roots.iter().find(|root| root.key == key) {
            if existing.doc_index != doc_index || !existing.pointer.is_empty() {
                return Err(schema_reference_error(
                    "external document URI resolves to multiple resources".to_string(),
                ));
            }
            return Ok(());
        }
        self.resource_roots.push(SchemaResourceRoot {
            doc_index,
            pointer: String::new(),
            key,
            base: base.clone(),
        });
        Ok(())
    }

    /// Walk OpenAPI Schema Object locations only (not the entire document tree).
    fn index_openapi_schemas(
        &mut self,
        root: &Value,
        base: &Url,
        depth: usize,
    ) -> Result<(), ExtractError> {
        if let Some(definitions) = root.get("definitions").and_then(Value::as_object) {
            self.index_schema_map(definitions, "/definitions", base, depth)?;
        }
        if let Some(parameters) = root.get("parameters").and_then(Value::as_object) {
            self.index_parameter_map(parameters, "/parameters", base, depth)?;
        }
        if let Some(responses) = root.get("responses").and_then(Value::as_object) {
            self.index_response_map(responses, "/responses", base, depth)?;
        }
        if let Some(components) = root.get("components").and_then(Value::as_object) {
            self.index_components(components, "/components", base, depth)?;
        }
        if let Some(paths) = root.get("paths").and_then(Value::as_object) {
            self.index_path_item_map(paths, "/paths", base, depth.min(MAX_PATH_ITEM_INDEX_DEPTH))?;
        }
        if let Some(webhooks) = root.get("webhooks").and_then(Value::as_object) {
            self.index_path_item_map(
                webhooks,
                "/webhooks",
                base,
                depth.min(MAX_PATH_ITEM_INDEX_DEPTH),
            )?;
        }
        Ok(())
    }

    fn index_components(
        &mut self,
        components: &Map<String, Value>,
        pointer: &str,
        base: &Url,
        depth: usize,
    ) -> Result<(), ExtractError> {
        if let Some(schemas) = components.get("schemas").and_then(Value::as_object) {
            self.index_schema_map(
                schemas,
                &append_json_pointer(pointer, "schemas"),
                base,
                depth,
            )?;
        }
        if let Some(parameters) = components.get("parameters").and_then(Value::as_object) {
            self.index_parameter_map(
                parameters,
                &append_json_pointer(pointer, "parameters"),
                base,
                depth,
            )?;
        }
        if let Some(headers) = components.get("headers").and_then(Value::as_object) {
            self.index_header_map(
                headers,
                &append_json_pointer(pointer, "headers"),
                base,
                depth,
            )?;
        }
        if let Some(request_bodies) = components.get("requestBodies").and_then(Value::as_object) {
            for (name, body) in request_bodies {
                let body_pointer =
                    append_json_pointer(&append_json_pointer(pointer, "requestBodies"), name);
                self.index_media_schema_container(body, &body_pointer, base, depth)?;
            }
        }
        if let Some(responses) = components.get("responses").and_then(Value::as_object) {
            self.index_response_map(
                responses,
                &append_json_pointer(pointer, "responses"),
                base,
                depth,
            )?;
        }
        if let Some(callbacks) = components.get("callbacks").and_then(Value::as_object) {
            for (name, callback) in callbacks {
                let callback_pointer =
                    append_json_pointer(&append_json_pointer(pointer, "callbacks"), name);
                if let Some(path_items) = callback.as_object() {
                    self.index_path_item_map(
                        path_items,
                        &callback_pointer,
                        base,
                        depth.min(MAX_PATH_ITEM_INDEX_DEPTH),
                    )?;
                }
            }
        }
        if let Some(path_items) = components.get("pathItems").and_then(Value::as_object) {
            self.index_path_item_map(
                path_items,
                &append_json_pointer(pointer, "pathItems"),
                base,
                depth.min(MAX_PATH_ITEM_INDEX_DEPTH),
            )?;
        }
        Ok(())
    }

    fn index_path_item_map(
        &mut self,
        items: &Map<String, Value>,
        pointer: &str,
        base: &Url,
        depth: usize,
    ) -> Result<(), ExtractError> {
        if depth == 0 {
            return Err(ExtractError::SchemaTooDeep {
                location: pointer.to_string(),
            });
        }
        for (name, item) in items {
            let item_pointer = append_json_pointer(pointer, name);
            let Some(item_object) = item.as_object() else {
                continue;
            };
            if let Some(parameters) = item_object.get("parameters").and_then(Value::as_array) {
                self.index_parameter_list(
                    parameters,
                    &append_json_pointer(&item_pointer, "parameters"),
                    base,
                    depth,
                )?;
            }
            for method in HTTP_METHODS {
                let Some(operation) = item_object.get(*method).and_then(Value::as_object) else {
                    continue;
                };
                let op_pointer = append_json_pointer(&item_pointer, method);
                if let Some(parameters) = operation.get("parameters").and_then(Value::as_array) {
                    self.index_parameter_list(
                        parameters,
                        &append_json_pointer(&op_pointer, "parameters"),
                        base,
                        depth,
                    )?;
                }
                if let Some(request_body) = operation.get("requestBody") {
                    self.index_media_schema_container(
                        request_body,
                        &append_json_pointer(&op_pointer, "requestBody"),
                        base,
                        depth,
                    )?;
                }
                if let Some(responses) = operation.get("responses").and_then(Value::as_object) {
                    self.index_response_map(
                        responses,
                        &append_json_pointer(&op_pointer, "responses"),
                        base,
                        depth,
                    )?;
                }
                if let Some(callbacks) = operation.get("callbacks").and_then(Value::as_object) {
                    for (cb_name, callback) in callbacks {
                        let cb_pointer = append_json_pointer(
                            &append_json_pointer(&op_pointer, "callbacks"),
                            cb_name,
                        );
                        if let Some(path_items) = callback.as_object() {
                            self.index_path_item_map(path_items, &cb_pointer, base, depth - 1)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn index_parameter_map(
        &mut self,
        parameters: &Map<String, Value>,
        pointer: &str,
        base: &Url,
        depth: usize,
    ) -> Result<(), ExtractError> {
        for (name, parameter) in parameters {
            self.index_parameter_object(
                parameter,
                &append_json_pointer(pointer, name),
                base,
                depth,
            )?;
        }
        Ok(())
    }

    fn index_parameter_list(
        &mut self,
        parameters: &[Value],
        pointer: &str,
        base: &Url,
        depth: usize,
    ) -> Result<(), ExtractError> {
        for (index, parameter) in parameters.iter().enumerate() {
            self.index_parameter_object(
                parameter,
                &append_json_pointer(pointer, &index.to_string()),
                base,
                depth,
            )?;
        }
        Ok(())
    }

    fn index_parameter_object(
        &mut self,
        parameter: &Value,
        pointer: &str,
        base: &Url,
        depth: usize,
    ) -> Result<(), ExtractError> {
        let Some(object) = parameter.as_object() else {
            return Ok(());
        };
        if let Some(schema) = object.get("schema") {
            self.index_schema(schema, base, &append_json_pointer(pointer, "schema"), depth)?;
        }
        self.index_media_schema_container(parameter, pointer, base, depth)
    }

    fn index_header_map(
        &mut self,
        headers: &Map<String, Value>,
        pointer: &str,
        base: &Url,
        depth: usize,
    ) -> Result<(), ExtractError> {
        for (name, header) in headers {
            self.index_parameter_object(header, &append_json_pointer(pointer, name), base, depth)?;
        }
        Ok(())
    }

    fn index_response_map(
        &mut self,
        responses: &Map<String, Value>,
        pointer: &str,
        base: &Url,
        depth: usize,
    ) -> Result<(), ExtractError> {
        for (status, response) in responses {
            let response_pointer = append_json_pointer(pointer, status);
            let Some(object) = response.as_object() else {
                continue;
            };
            // Swagger 2.0 response schema.
            if let Some(schema) = object.get("schema") {
                self.index_schema(
                    schema,
                    base,
                    &append_json_pointer(&response_pointer, "schema"),
                    depth,
                )?;
            }
            if let Some(headers) = object.get("headers").and_then(Value::as_object) {
                self.index_header_map(
                    headers,
                    &append_json_pointer(&response_pointer, "headers"),
                    base,
                    depth,
                )?;
            }
            self.index_media_schema_container(response, &response_pointer, base, depth)?;
        }
        Ok(())
    }

    fn index_media_schema_container(
        &mut self,
        container: &Value,
        pointer: &str,
        base: &Url,
        depth: usize,
    ) -> Result<(), ExtractError> {
        let Some(content) = container.get("content").and_then(Value::as_object) else {
            return Ok(());
        };
        for (media_type, media) in content {
            let media_pointer =
                append_json_pointer(&append_json_pointer(pointer, "content"), media_type);
            if let Some(schema) = media.get("schema") {
                self.index_schema(
                    schema,
                    base,
                    &append_json_pointer(&media_pointer, "schema"),
                    depth,
                )?;
            }
        }
        Ok(())
    }

    fn index_schema_map(
        &mut self,
        schemas: &Map<String, Value>,
        pointer: &str,
        base: &Url,
        depth: usize,
    ) -> Result<(), ExtractError> {
        for (name, schema) in schemas {
            self.index_schema(schema, base, &append_json_pointer(pointer, name), depth)?;
        }
        Ok(())
    }

    /// Index a Schema Object: interpret `$id`/`$anchor` here, then only descend
    /// into applicator / definition keywords that hold subschemas.
    fn index_schema(
        &mut self,
        value: &Value,
        base: &Url,
        pointer: &str,
        depth: usize,
    ) -> Result<(), ExtractError> {
        if depth == 0 {
            return Err(ExtractError::SchemaTooDeep {
                location: pointer.to_string(),
            });
        }
        let Value::Object(object) = value else {
            // Boolean schemas and non-objects have no identifier keywords.
            return Ok(());
        };
        let child_base = self.index_object_keywords(object, base, pointer)?;
        self.index_subschemas(object, &child_base, pointer, depth - 1)
    }

    fn index_subschemas(
        &mut self,
        object: &Map<String, Value>,
        base: &Url,
        pointer: &str,
        depth: usize,
    ) -> Result<(), ExtractError> {
        for key in [
            "properties",
            "patternProperties",
            "dependentSchemas",
            "$defs",
            "definitions",
        ] {
            if let Some(map) = object.get(key).and_then(Value::as_object) {
                self.index_schema_map(map, &append_json_pointer(pointer, key), base, depth)?;
            }
        }
        for key in ["allOf", "anyOf", "oneOf", "prefixItems"] {
            if let Some(values) = object.get(key).and_then(Value::as_array) {
                for (index, child) in values.iter().enumerate() {
                    self.index_schema(
                        child,
                        base,
                        &append_json_pointer(
                            &append_json_pointer(pointer, key),
                            &index.to_string(),
                        ),
                        depth,
                    )?;
                }
            }
        }
        for key in [
            "additionalProperties",
            "unevaluatedProperties",
            "additionalItems",
            "unevaluatedItems",
            "contains",
            "not",
            "if",
            "then",
            "else",
            "propertyNames",
            "contentSchema",
        ] {
            if let Some(child) = object.get(key) {
                self.index_schema(child, base, &append_json_pointer(pointer, key), depth)?;
            }
        }
        // Draft 7 `items` may be a schema or a tuple array; 2020-12 is a schema.
        match object.get("items") {
            Some(Value::Array(values)) => {
                for (index, child) in values.iter().enumerate() {
                    self.index_schema(
                        child,
                        base,
                        &append_json_pointer(
                            &append_json_pointer(pointer, "items"),
                            &index.to_string(),
                        ),
                        depth,
                    )?;
                }
            }
            Some(child) => {
                self.index_schema(child, base, &append_json_pointer(pointer, "items"), depth)?;
            }
            None => {}
        }
        // Draft 7 `dependencies`: object values may be schemas or property-name arrays.
        if let Some(dependencies) = object.get("dependencies").and_then(Value::as_object) {
            for (name, child) in dependencies {
                if child.is_object() {
                    self.index_schema(
                        child,
                        base,
                        &append_json_pointer(&append_json_pointer(pointer, "dependencies"), name),
                        depth,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn index_object_keywords(
        &mut self,
        object: &Map<String, Value>,
        base: &Url,
        pointer: &str,
    ) -> Result<Url, ExtractError> {
        let mut child_base = base.clone();

        let id_value = object
            .get("$id")
            .or_else(|| {
                if self.use_dollar_anchor {
                    None
                } else {
                    object.get("id")
                }
            })
            .and_then(Value::as_str);

        if let Some(id_value) = id_value {
            let resolved = base
                .join(id_value)
                .map_err(|_| schema_reference_error(format!("invalid schema $id '{id_value}'")))?;
            let fragment = resolved.fragment().unwrap_or("");
            if !fragment.is_empty() {
                if self.use_dollar_anchor {
                    return Err(schema_reference_error(format!(
                        "schema $id '{id_value}' must not contain a non-empty fragment under Draft 2020-12"
                    )));
                }
                // Draft 7 / OAS 3.0 / Swagger: fragment-only `$id`/`id` defines a plain-name anchor.
                if !is_valid_draft7_anchor_name(fragment) {
                    return Err(schema_reference_error(format!(
                        "invalid schema anchor in $id '{id_value}'"
                    )));
                }
                let mut resource = resolved.clone();
                resource.set_fragment(None);
                let resource_uri = resource_uri_key(&resource);
                if resource_uri != resource_uri_key(base) {
                    self.register_resource_root(pointer, &resource, id_value)?;
                }
                // Same-resource fragment `$id`/`id` only registers an anchor; the
                // enclosing resource root is already indexed.
                self.register_anchor(&resource_uri, fragment, pointer)?;
                child_base = resource;
            } else {
                self.register_resource_root(pointer, &resolved, id_value)?;
                child_base = resolved;
            }
        }

        if self.use_dollar_anchor
            && let Some(anchor) = object.get("$anchor").and_then(Value::as_str)
        {
            if !is_valid_2020_anchor_name(anchor) {
                return Err(schema_reference_error(format!(
                    "invalid $anchor '{anchor}'"
                )));
            }
            let resource_uri = resource_uri_key(&child_base);
            self.register_anchor(&resource_uri, anchor, pointer)?;
        }

        Ok(child_base)
    }

    fn register_resource_root(
        &mut self,
        pointer: &str,
        base: &Url,
        id_value: &str,
    ) -> Result<(), ExtractError> {
        let key = resource_uri_key(base);
        if let Some(existing) = self.resource_roots.iter().find(|root| root.key == key) {
            if existing.pointer != pointer || existing.doc_index != self.indexing_doc {
                return Err(schema_reference_error(format!(
                    "duplicate schema $id '{id_value}'"
                )));
            }
            return Ok(());
        }
        self.resource_roots.push(SchemaResourceRoot {
            doc_index: self.indexing_doc,
            pointer: pointer.to_string(),
            key,
            base: base.clone(),
        });
        Ok(())
    }

    fn register_anchor(
        &mut self,
        resource_uri: &str,
        anchor: &str,
        pointer: &str,
    ) -> Result<(), ExtractError> {
        let entry = self.anchors.entry(resource_uri.to_string()).or_default();
        if let Some(existing) = entry.get(anchor) {
            if existing != pointer {
                return Err(schema_reference_error(format!(
                    "duplicate schema anchor '{anchor}'"
                )));
            }
            return Ok(());
        }
        entry.insert(anchor.to_string(), pointer.to_string());
        Ok(())
    }

    /// Return the base in force immediately before the schema at `pointer`
    /// applies its own `$id`. An exact resource-root match must therefore be
    /// excluded: `resolve_refs` will process that target object's `$id` once.
    fn parent_resource_for_pointer(&self, doc_index: usize, pointer: &str) -> &Url {
        for root in &self.resource_roots {
            if root.doc_index != doc_index {
                continue;
            }
            if root.pointer.is_empty() {
                continue;
            }
            if pointer
                .strip_prefix(&root.pointer)
                .is_some_and(|suffix| suffix.starts_with('/'))
            {
                return &root.base;
            }
        }
        &self.documents[doc_index].base
    }

    fn resource_root_by_key(&self, resource_uri: &str) -> Option<&SchemaResourceRoot> {
        self.resource_roots
            .iter()
            .find(|root| root.key == resource_uri)
    }

    fn resolve_reference<'a>(
        &'a self,
        reference: &str,
        current_base: &Url,
    ) -> Result<ResolvedRef<'a>, ExtractError> {
        let (uri_part, raw_fragment) = split_ref_uri_and_fragment(reference);
        let decoded_fragment = decode_uri_fragment(raw_fragment, reference)?;

        let target_resource = match uri_part {
            None => {
                let mut resource = current_base.clone();
                resource.set_fragment(None);
                resource
            }
            Some(uri) => {
                let joined = current_base.join(uri).map_err(|_| {
                    schema_reference_error(format!("invalid internal $ref '{reference}'"))
                })?;
                let mut resource = joined;
                resource.set_fragment(None);
                resource
            }
        };

        let resource_key = resource_uri_key(&target_resource);
        let Some(resource_root_meta) = self.resource_root_by_key(&resource_key) else {
            return Err(ExtractError::UnsupportedExternalRef {
                reference: redact_reference(reference),
            });
        };
        let doc_index = resource_root_meta.doc_index;
        let resource_root_pointer = resource_root_meta.pointer.as_str();
        let document_root = &self.documents[doc_index].root;
        let root_is_schema = self.documents[doc_index].root_is_schema;

        if is_json_pointer_fragment(&decoded_fragment) {
            let resource_root = if resource_root_pointer.is_empty() {
                document_root
            } else {
                document_root
                    .pointer(resource_root_pointer)
                    .ok_or_else(|| {
                        schema_reference_error(unresolved_internal_ref_message(
                            reference,
                            &resource_key,
                            resource_root_pointer,
                        ))
                    })?
            };
            // Empty fragment = schema resource root. The OpenAPI document root
            // (synthetic / envelope document base) is not a Schema Object; bare
            // `#` against it must not expand the whole document. Schema-only
            // external documents *are* Schema Objects at the document root.
            let target = if decoded_fragment.is_empty() {
                if resource_root_pointer.is_empty() && !root_is_schema {
                    return Err(schema_reference_error(format!(
                        "unresolved internal $ref '{reference}': OpenAPI document root is not a Schema Object"
                    )));
                }
                resource_root
            } else {
                resource_root.pointer(&decoded_fragment).ok_or_else(|| {
                    schema_reference_error(unresolved_internal_ref_message(
                        reference,
                        &resource_key,
                        resource_root_pointer,
                    ))
                })?
            };
            let absolute_pointer = if decoded_fragment.is_empty() {
                resource_root_pointer.to_string()
            } else if resource_root_pointer.is_empty() {
                decoded_fragment.clone()
            } else {
                format!("{resource_root_pointer}{decoded_fragment}")
            };
            return Ok(ResolvedRef {
                target,
                target_base: self
                    .parent_resource_for_pointer(doc_index, &absolute_pointer)
                    .clone(),
                document_root,
            });
        }

        if !self.valid_anchor_name(&decoded_fragment) {
            return Err(schema_reference_error(format!(
                "invalid plain-name fragment in $ref '{reference}'"
            )));
        }

        let anchor_resource_key = resource_uri_key(&resource_root_meta.base);
        let pointer = self
            .anchors
            .get(&anchor_resource_key)
            .and_then(|anchors| anchors.get(&decoded_fragment))
            .ok_or_else(|| {
                schema_reference_error(format!("unresolved internal $ref '{reference}'"))
            })?;
        let target = if pointer.is_empty() {
            document_root
        } else {
            document_root.pointer(pointer).ok_or_else(|| {
                schema_reference_error(format!("unresolved internal $ref '{reference}'"))
            })?
        };
        Ok(ResolvedRef {
            target,
            target_base: self.parent_resource_for_pointer(doc_index, pointer).clone(),
            document_root,
        })
    }

    fn valid_anchor_name(&self, name: &str) -> bool {
        if self.use_dollar_anchor {
            is_valid_2020_anchor_name(name)
        } else {
            is_valid_draft7_anchor_name(name)
        }
    }

    fn child_base_for_object(
        &self,
        object: &Map<String, Value>,
        base: &Url,
    ) -> Result<Url, ExtractError> {
        let id_value = object
            .get("$id")
            .or_else(|| {
                if self.use_dollar_anchor {
                    None
                } else {
                    object.get("id")
                }
            })
            .and_then(Value::as_str);
        let Some(id_value) = id_value else {
            return Ok(base.clone());
        };
        let resolved = base
            .join(id_value)
            .map_err(|_| schema_reference_error(format!("invalid schema $id '{id_value}'")))?;
        let mut resource = resolved;
        resource.set_fragment(None);
        Ok(resource)
    }
}

/// True when `value` is a standalone Schema Object document rather than an
/// OpenAPI/Swagger envelope (`openapi` / `swagger` / `paths` / `components`).
fn is_schema_only_document(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        // Boolean schemas and non-objects are schema documents.
        return true;
    };
    let has_openapi_shape = object.contains_key("openapi")
        || object.contains_key("swagger")
        || object.contains_key("paths")
        || object.contains_key("components");
    if has_openapi_shape {
        return false;
    }
    // No OpenAPI envelope — treat as a JSON Schema / schema-only document.
    // Also covers roots that look like Schema Objects (`$id`, `$schema`, type, …).
    true
}

/// A JSON-pointer fragment resolves *inside* the schema resource in force at the
/// reference, not against the OpenAPI document root. When an enclosing or
/// adjacent `$id` rebased that resource, a pointer such as
/// `#/components/schemas/Order` silently stops addressing the document, so name
/// the resource that was searched instead of reporting a bare "unresolved".
/// Both interpolated values come from the submitted spec and are already the
/// same trust class as `reference`; no resolver-internal state is disclosed.
fn unresolved_internal_ref_message(
    reference: &str,
    resource_key: &str,
    resource_root_pointer: &str,
) -> String {
    if resource_root_pointer.is_empty() {
        return format!("unresolved internal $ref '{reference}'");
    }
    format!(
        "unresolved internal $ref '{reference}': the fragment is resolved inside the schema resource '{resource_key}' (rooted at '{resource_root_pointer}' by its $id), not against the OpenAPI document root; use an absolute $ref or move the $id"
    )
}

fn resource_uri_key(url: &Url) -> String {
    let mut owned = url.clone();
    owned.set_fragment(None);
    normalize_percent_escape_case(owned.as_str())
}

fn normalize_percent_escape_case(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut remaining = value;
    while let Some(offset) = remaining.find('%') {
        normalized.push_str(&remaining[..offset]);
        let escape = &remaining[offset..];
        if escape.len() >= 3
            && escape.as_bytes()[1].is_ascii_hexdigit()
            && escape.as_bytes()[2].is_ascii_hexdigit()
        {
            normalized.push('%');
            normalized.push(char::from(escape.as_bytes()[1].to_ascii_uppercase()));
            normalized.push(char::from(escape.as_bytes()[2].to_ascii_uppercase()));
            remaining = &escape[3..];
        } else {
            normalized.push('%');
            remaining = &escape[1..];
        }
    }
    normalized.push_str(remaining);
    normalized
}

fn append_json_pointer(base: &str, token: &str) -> String {
    let escaped = token.replace('~', "~0").replace('/', "~1");
    format!("{base}/{escaped}")
}

fn split_ref_uri_and_fragment(reference: &str) -> (Option<&str>, &str) {
    match reference.split_once('#') {
        None => (Some(reference), ""),
        Some(("", fragment)) => (None, fragment),
        Some((uri, fragment)) => (Some(uri), fragment),
    }
}

fn decode_uri_fragment(raw: &str, reference: &str) -> Result<String, ExtractError> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(schema_reference_error(format!(
                        "malformed percent-encoding in $ref '{reference}'"
                    )));
                }
                let hi = hex_nibble(bytes[index + 1]).ok_or_else(|| {
                    schema_reference_error(format!(
                        "malformed percent-encoding in $ref '{reference}'"
                    ))
                })?;
                let lo = hex_nibble(bytes[index + 2]).ok_or_else(|| {
                    schema_reference_error(format!(
                        "malformed percent-encoding in $ref '{reference}'"
                    ))
                })?;
                out.push((hi << 4) | lo);
                index += 3;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| {
        schema_reference_error(format!("malformed percent-encoding in $ref '{reference}'"))
    })
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_json_pointer_fragment(decoded: &str) -> bool {
    decoded.is_empty() || decoded.starts_with('/')
}

fn is_valid_2020_anchor_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
}

fn is_valid_draft7_anchor_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':'))
}

fn schema_reference_error(message: String) -> ExtractError {
    ExtractError::SchemaReference(message)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum ResolveContext {
    ReferenceObject,
    Schema,
    SchemaMap,
    SchemaArray,
    Opaque,
}

fn schema_child_context(key: &str, value: &Value) -> ResolveContext {
    match key {
        "$defs" | "definitions" | "properties" | "patternProperties" | "dependentSchemas"
        | "dependencies" => ResolveContext::SchemaMap,
        "allOf" | "anyOf" | "oneOf" | "prefixItems" => ResolveContext::SchemaArray,
        "items" if value.is_array() => ResolveContext::SchemaArray,
        "items"
        | "additionalProperties"
        | "unevaluatedProperties"
        | "additionalItems"
        | "unevaluatedItems"
        | "contains"
        | "not"
        | "if"
        | "then"
        | "else"
        | "propertyNames"
        | "contentSchema" => ResolveContext::Schema,
        _ => ResolveContext::Opaque,
    }
}

/// Schema Object keywords that assert nothing about an instance: identifier /
/// dialect / subschema-container keywords and pure annotations. They stay on
/// the composition wrapper, which is the position they already occupied, so
/// identifier and base-URI scope is unchanged.
const SCHEMA_NON_ASSERTION_KEYWORDS: &[&str] = &[
    "$anchor",
    "$comment",
    "$defs",
    "$dynamicAnchor",
    "$id",
    "$schema",
    "$vocabulary",
    "default",
    "definitions",
    "deprecated",
    "description",
    "discriminator",
    "example",
    "examples",
    "externalDocs",
    "format",
    "id",
    "readOnly",
    "summary",
    "title",
    "writeOnly",
    "xml",
    "contentEncoding",
    "contentMediaType",
    "contentSchema",
    "$recursiveAnchor",
];

/// Schema Object keywords Ferrum cannot faithfully relocate into a composition
/// branch. `unevaluatedProperties` / `unevaluatedItems` are evaluated against
/// annotations produced by applicators in the *same* schema object — including
/// the adjacent `$ref` — which a separate `allOf` branch does not see, and
/// `$dynamicRef` resolution depends on the dynamic scope. Importing either next
/// to `$ref` would change meaning, so they fail closed instead.
const UNPRESERVABLE_REF_SIBLING_KEYWORDS: &[&str] = &[
    "$dynamicRef",
    "$recursiveRef",
    "unevaluatedItems",
    "unevaluatedProperties",
];

/// Resolution context for one Schema Object `$ref`-with-siblings composition:
/// the *referring* document root (for sibling keyword resolution), the reporting
/// location, the reference being composed, the remaining recursion budget, the
/// base URI in force inside the referring object (after its own `$id`), and the
/// shared resolver. The referenced target is expanded separately against its
/// own document root before this composition runs.
struct RefComposition<'a, 'b> {
    root: &'a Value,
    location: &'a str,
    reference: &'a str,
    depth: usize,
    child_base: &'a Url,
    resolver: &'a LocalSchemaResolver,
    state: &'b mut ResolutionState,
}

/// Compose a Schema Object `$ref` with its adjacent keywords without letting an
/// adjacent keyword overwrite a referenced assertion (GHSA-rf4j-rhmf-8whm).
///
/// - A bare `$id` / `id` beside `$ref` only rebases that reference. After the
///   target is materialized the identifier is dropped rather than wrapping the
///   target in `allOf`, so referenced assertions stay at the schema root.
/// - Other identifier and annotation keywords stay on the wrapper; they assert
///   nothing, so keeping them in place preserves both meaning and `$id` scope
///   when further URI-reference or annotation siblings remain.
/// - OpenAPI 3.1+ (JSON Schema 2020-12): `$ref` is an applicator and adjacent
///   assertions are independent, so the pair becomes
///   `{<annotations>, allOf: [<referenced schema>, {<adjacent assertions>}]}`,
///   which is exactly "both must hold".
/// - Swagger 2.0 / OpenAPI 3.0: Schema Object `$ref` is a JSON Reference and
///   adjacent keywords have no defined meaning. Rather than silently dropping
///   an operator-visible constraint or applying the 3.1 rule to a document that
///   did not opt into it, the import fails closed and asks for an explicit
///   `allOf`.
fn compose_schema_ref_siblings(
    ctx: RefComposition<'_, '_>,
    object: &Map<String, Value>,
    resolved_target: Value,
) -> Result<Value, ExtractError> {
    let RefComposition {
        root,
        location,
        reference,
        depth,
        child_base,
        resolver,
        state,
    } = ctx;
    let mut wrapper_fields = Map::new();
    let mut assertions = Map::new();
    for (key, child) in object {
        if key == "$ref" {
            continue;
        }
        if UNPRESERVABLE_REF_SIBLING_KEYWORDS.contains(&key.as_str()) {
            return Err(schema_reference_error(format!(
                "$ref '{reference}' at {location} has an adjacent '{key}' keyword, whose evaluation scope cannot be preserved; move the reference into an explicit allOf branch"
            )));
        }
        let resolved_child = resolve_refs_bounded(
            root,
            child,
            location,
            depth - 1,
            child_base,
            resolver,
            schema_child_context(key, child),
            state,
        )?;
        if SCHEMA_NON_ASSERTION_KEYWORDS.contains(&key.as_str())
            || key.starts_with("x-")
            || (resolver.schema_object_ref_siblings && key == "nullable")
        {
            wrapper_fields.insert(key.clone(), resolved_child);
        } else {
            assertions.insert(key.clone(), resolved_child);
        }
    }

    if !assertions.is_empty() && !resolver.schema_object_ref_siblings {
        let mut keywords: Vec<&str> = assertions.keys().map(String::as_str).collect();
        keywords.sort_unstable();
        return Err(schema_reference_error(format!(
            "$ref '{reference}' at {location} has adjacent assertion keyword(s) ({}); Swagger 2.0 and OpenAPI 3.0 Schema Object $ref is a JSON Reference with no defined sibling semantics, so wrap the reference in an explicit allOf instead",
            keywords.join(", ")
        )));
    }

    if wrapper_fields.is_empty() && assertions.is_empty() {
        return Ok(resolved_target);
    }

    // A bare `$id` / `id` beside `$ref` only rebases that reference during
    // resolution (2020-12 §8.2.1). Once the target is materialized there is no
    // remaining URI-reference sibling that needs the wrapper resource identity,
    // and wrapping the target in `allOf` solely to retain `$id` buries
    // referenced assertions (for example `required`) under `allOf[0]` — which
    // breaks the generated validator-config contract external-ref tests pin at
    // the schema root. Annotation or assertion siblings still need the wrapper.
    if assertions.is_empty()
        && wrapper_fields
            .keys()
            .all(|key| matches!(key.as_str(), "$id" | "id"))
    {
        return Ok(resolved_target);
    }

    consume_resolution_budget(state, location, 1, 2)?;
    let mut wrapper = wrapper_fields;
    let mut branches = vec![resolved_target];
    if !assertions.is_empty() {
        consume_resolution_budget(state, location, 1, 2)?;
        branches.push(Value::Object(assertions));
    }
    wrapper.insert("allOf".to_string(), Value::Array(branches));
    Ok(Value::Object(wrapper))
}

/// Expand one schema / reference position under the document-scoped account.
///
/// The per-expansion budget is reset here, so the documented single-expansion
/// ceiling still applies to each schema individually, while the document
/// account in `state` keeps accumulating across every expansion site.
#[allow(clippy::too_many_arguments)]
fn resolve_refs(
    root: &Value,
    value: &Value,
    location: &str,
    depth: usize,
    current_base: &Url,
    resolver: &LocalSchemaResolver,
    context: ResolveContext,
    state: &mut ResolutionState,
) -> Result<Value, ExtractError> {
    state.expansion = ResolutionBudget {
        remaining_nodes: MAX_RESOLVED_SCHEMA_NODES,
        remaining_bytes: MAX_OPENAPI_VALIDATOR_CONFIG_SIZE,
    };
    resolve_refs_bounded(
        root,
        value,
        location,
        depth,
        current_base,
        resolver,
        context,
        state,
    )
}

struct ResolutionBudget {
    remaining_nodes: usize,
    remaining_bytes: usize,
}

/// Identity of a `$ref` target within the owned document set.
///
/// Every target is borrowed out of a `ResolverDocument` root tree owned by the
/// resolver, so the address of the target node uniquely identifies it across
/// the primary and external documents. Using node identity (rather than the
/// `$ref` literal) makes cycle detection independent of how a target is
/// spelled: a pointer fragment, a plain-name anchor, and an `$id`-rebased
/// relative reference that all land on the same node are the same target.
type RefTargetId = usize;

fn ref_target_id(target: &Value) -> RefTargetId {
    std::ptr::from_ref(target) as RefTargetId
}

/// Memoization key for a completed reference expansion.
///
/// `depth` is part of the key on purpose. The remaining-depth ceiling is a
/// documented part of the import contract, and the same target expanded with
/// less remaining depth may legitimately be rejected where a shallower
/// occurrence succeeded. Keying on it preserves that boundary exactly while
/// still collapsing a high-branching DAG from exponential re-expansion to at
/// most `MAX_SCHEMA_REF_DEPTH` expansions per target.
#[derive(PartialEq, Eq, Hash)]
struct MemoKey {
    target: RefTargetId,
    context: ResolveContext,
    depth: usize,
}

/// A previously computed expansion plus the exact budget it cost.
///
/// Reuse still clones the value into its new position, so reuse is charged the
/// same nodes/bytes the original computation was charged. Memoization removes
/// duplicated *work*, never duplicated *accounting*.
struct MemoEntry {
    value: Arc<Value>,
    nodes: usize,
    bytes: usize,
}

/// Document-scoped reference-resolution state.
///
/// Holds the cumulative account, the active reference chain used for immediate
/// cycle rejection, and the expansion memo. One instance covers a whole
/// document import.
struct ResolutionState {
    /// Cumulative across every expansion site in the document.
    document: ResolutionBudget,
    /// Reset per [`resolve_refs`] call.
    expansion: ResolutionBudget,
    /// `$ref` literals for the targets currently being expanded, outermost first.
    active_path: Vec<String>,
    /// Membership index for `active_path`, keyed by target node identity.
    active_targets: HashSet<RefTargetId>,
    memo: HashMap<MemoKey, MemoEntry>,
}

impl ResolutionState {
    fn new() -> Self {
        Self {
            document: ResolutionBudget {
                remaining_nodes: MAX_TOTAL_RESOLVED_SCHEMA_NODES,
                remaining_bytes: MAX_TOTAL_RESOLVED_SCHEMA_BYTES,
            },
            expansion: ResolutionBudget {
                remaining_nodes: MAX_RESOLVED_SCHEMA_NODES,
                remaining_bytes: MAX_OPENAPI_VALIDATOR_CONFIG_SIZE,
            },
            active_path: Vec::new(),
            active_targets: HashSet::new(),
            memo: HashMap::new(),
        }
    }

    /// The reference chain that closed a cycle, rendered for the error message.
    ///
    /// Only `$ref` literals from the submitted document appear here.
    fn cycle_path(&self, closing_reference: &str) -> String {
        let mut path = self.active_path.join(" -> ");
        if path.is_empty() {
            closing_reference.to_string()
        } else {
            path.push_str(" -> ");
            path.push_str(closing_reference);
            path
        }
    }
}

/// Charge `nodes`/`bytes` against both the per-expansion and the document
/// account before the corresponding memory is materialized.
fn consume_resolution_budget(
    state: &mut ResolutionState,
    location: &str,
    nodes: usize,
    bytes: usize,
) -> Result<(), ExtractError> {
    for budget in [&mut state.expansion, &mut state.document] {
        let Some(remaining_nodes) = budget.remaining_nodes.checked_sub(nodes) else {
            return Err(ExtractError::SchemaTooLarge {
                location: location.to_string(),
            });
        };
        let Some(remaining_bytes) = budget.remaining_bytes.checked_sub(bytes) else {
            return Err(ExtractError::SchemaTooLarge {
                location: location.to_string(),
            });
        };
        budget.remaining_nodes = remaining_nodes;
        budget.remaining_bytes = remaining_bytes;
    }
    Ok(())
}

/// Charge the weight of a subtree that is about to be cloned wholesale, minus
/// the container weight the caller already charged.
///
/// Whole-subtree clones (`Opaque` positions, Reference Objects that carry no
/// `$ref`, and non-schema arrays) previously escaped accounting: only the
/// container's shallow weight was charged while the entire subtree was cloned.
/// A document could then repeat one large clone target across many references
/// and materialize unbounded memory while staying well inside every declared
/// budget.
fn consume_subtree_clone_budget(
    state: &mut ResolutionState,
    location: &str,
    value: &Value,
) -> Result<(), ExtractError> {
    let (nodes, bytes) = opaque_value_weight(value);
    consume_resolution_budget(
        state,
        location,
        nodes.saturating_sub(1),
        bytes.saturating_sub(shallow_value_bytes(value)),
    )
}

fn opaque_value_weight(value: &Value) -> (usize, usize) {
    match value {
        Value::Null => (1, 4),
        Value::Bool(true) => (1, 4),
        Value::Bool(false) => (1, 5),
        Value::Number(number) => (1, number.to_string().len()),
        Value::String(value) => (1, json_string_serialized_len(value)),
        Value::Array(values) => values.iter().fold((1usize, 2usize), |weight, child| {
            let child = opaque_value_weight(child);
            (
                weight.0.saturating_add(child.0),
                weight.1.saturating_add(child.1).saturating_add(1),
            )
        }),
        Value::Object(object) => object
            .iter()
            .fold((1usize, 2usize), |weight, (key, child)| {
                let child = opaque_value_weight(child);
                (
                    weight.0.saturating_add(child.0),
                    weight
                        .1
                        .saturating_add(json_string_serialized_len(key))
                        .saturating_add(child.1)
                        .saturating_add(2),
                )
            }),
    }
}

/// Exact byte length of a string after `serde_json` quoting/escaping.
///
/// Resolver and operation budgets must count the representation that will
/// actually be serialized. Counting decoded UTF-8 bytes alone underestimates
/// attacker-controlled quotes, backslashes, and control characters by up to
/// six bytes each.
fn json_string_serialized_len(value: &str) -> usize {
    value.chars().fold(2usize, |bytes, character| {
        let encoded = match character {
            '"' | '\\' | '\u{0008}' | '\u{0009}' | '\u{000a}' | '\u{000c}' | '\u{000d}' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            _ => character.len_utf8(),
        };
        bytes.saturating_add(encoded)
    })
}

fn shallow_value_bytes(value: &Value) -> usize {
    match value {
        Value::Null => 4,
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(number) => number.to_string().len(),
        Value::String(value) => json_string_serialized_len(value),
        Value::Array(values) => values.len().saturating_add(2),
        Value::Object(object) => object.keys().fold(2usize, |bytes, key| {
            bytes
                .saturating_add(json_string_serialized_len(key))
                .saturating_add(2)
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_refs_bounded(
    root: &Value,
    value: &Value,
    location: &str,
    depth: usize,
    current_base: &Url,
    resolver: &LocalSchemaResolver,
    context: ResolveContext,
    state: &mut ResolutionState,
) -> Result<Value, ExtractError> {
    if context == ResolveContext::Opaque {
        let (nodes, bytes) = opaque_value_weight(value);
        consume_resolution_budget(state, location, nodes, bytes)?;
        return Ok(value.clone());
    }
    if depth == 0 {
        return Err(ExtractError::SchemaTooDeep {
            location: location.to_string(),
        });
    }
    consume_resolution_budget(state, location, 1, shallow_value_bytes(value))?;
    match value {
        Value::Object(object) => {
            let child_base = if context == ResolveContext::Schema {
                // `$id` on this Schema Object establishes the base URI for every
                // URI-reference keyword in the same object, including `$ref`.
                resolver.child_base_for_object(object, current_base)?
            } else {
                current_base.clone()
            };
            let resolves_own_reference = matches!(
                context,
                ResolveContext::Schema | ResolveContext::ReferenceObject
            );
            if resolves_own_reference
                && let Some(reference) = object.get("$ref").and_then(Value::as_str)
            {
                // Refs whose absolute URI is not an indexed resource (including
                // external URIs when policy did not admit them) are rejected
                // inside `resolve_reference` as UnsupportedExternalRef.
                let resolved_ref = resolver.resolve_reference(reference, &child_base)?;
                let mut resolved = resolve_ref_target(
                    resolved_ref.document_root,
                    resolved_ref.target,
                    &resolved_ref.target_base,
                    reference,
                    depth,
                    resolver,
                    context,
                    state,
                )?;
                if object.len() > 1 {
                    if context == ResolveContext::Schema {
                        // Schema Object: never merge keywords by replacement.
                        // Sibling keywords stay in the *referring* document.
                        return compose_schema_ref_siblings(
                            RefComposition {
                                root,
                                location,
                                reference,
                                depth,
                                child_base: &child_base,
                                resolver,
                                state,
                            },
                            object,
                            resolved,
                        );
                    }
                    // Reference Object (Path Item / requestBody / response /
                    // parameter / header positions). These are not Schema
                    // Objects and keep Ferrum's documented deterministic
                    // sibling overlay; OpenAPI leaves the conflict undefined
                    // for Path Items and the referenced object is not a
                    // constraint set.
                    if let Some(resolved_object) = resolved.as_object_mut() {
                        for (key, child) in object {
                            if key != "$ref" {
                                resolved_object.insert(
                                    key.clone(),
                                    resolve_refs_bounded(
                                        root,
                                        child,
                                        location,
                                        depth - 1,
                                        &child_base,
                                        resolver,
                                        ResolveContext::Opaque,
                                        state,
                                    )?,
                                );
                            }
                        }
                    }
                }
                return Ok(resolved);
            }
            if context == ResolveContext::ReferenceObject {
                // Whole-subtree clone: charge everything below the container,
                // which the shallow charge above did not cover.
                consume_subtree_clone_budget(state, location, value)?;
                return Ok(value.clone());
            }
            let mut resolved = Map::new();
            for (key, child) in object {
                let child_context = match context {
                    ResolveContext::Schema => schema_child_context(key, child),
                    ResolveContext::SchemaMap => ResolveContext::Schema,
                    _ => ResolveContext::Opaque,
                };
                resolved.insert(
                    key.clone(),
                    resolve_refs_bounded(
                        root,
                        child,
                        location,
                        depth - 1,
                        &child_base,
                        resolver,
                        child_context,
                        state,
                    )?,
                );
            }
            Ok(Value::Object(resolved))
        }
        Value::Array(values) if context == ResolveContext::SchemaArray => values
            .iter()
            .map(|child| {
                resolve_refs_bounded(
                    root,
                    child,
                    location,
                    depth - 1,
                    current_base,
                    resolver,
                    ResolveContext::Schema,
                    state,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        other => {
            // Arrays that are not schema arrays (and every scalar) are cloned
            // wholesale. Nested array contents are not covered by the shallow
            // charge above, so account for them before cloning.
            consume_subtree_clone_budget(state, location, other)?;
            Ok(other.clone())
        }
    }
}

/// Expand a `$ref` target, rejecting cycles immediately and reusing a prior
/// identical expansion instead of recomputing it (GHSA-8jc7-c52g-85xr).
///
/// `root` is the document root that owns `target` (which may differ from the
/// referring document when resolving a cross-document `$ref`). Nested refs
/// inside the target expand against this root; sibling keywords on the
/// referring object continue to use the referring document root at the
/// `resolve_refs_bounded` call site.
///
/// Cycle rejection happens the moment a target that is still on the active
/// chain is re-entered, so a self-cycle or a mutual cycle fails without first
/// expanding the remaining depth budget's worth of sibling branches.
///
/// Memoization is what keeps a high-branching acyclic DAG from re-expanding
/// exponentially: the same `(target, context, remaining depth)` is computed
/// once and afterwards only cloned. Because reuse is charged the recorded cost,
/// total materialization stays bounded by the document account and total work
/// stays proportional to it.
#[allow(clippy::too_many_arguments)]
fn resolve_ref_target(
    root: &Value,
    target: &Value,
    target_base: &Url,
    reference: &str,
    depth: usize,
    resolver: &LocalSchemaResolver,
    context: ResolveContext,
    state: &mut ResolutionState,
) -> Result<Value, ExtractError> {
    let target_id = ref_target_id(target);
    if state.active_targets.contains(&target_id) {
        return Err(ExtractError::SchemaReferenceCycle {
            path: state.cycle_path(reference),
        });
    }
    let key = MemoKey {
        target: target_id,
        context,
        depth: depth - 1,
    };
    // Take a cheap handle first so the deep clone still happens *after* the
    // budget for it has been charged.
    let cached = state
        .memo
        .get(&key)
        .map(|entry| (Arc::clone(&entry.value), entry.nodes, entry.bytes));
    if let Some((value, nodes, bytes)) = cached {
        consume_resolution_budget(state, reference, nodes, bytes)?;
        return Ok(value.as_ref().clone());
    }

    state.active_targets.insert(target_id);
    state.active_path.push(reference.to_string());
    let before_nodes = state.document.remaining_nodes;
    let before_bytes = state.document.remaining_bytes;
    let resolved = resolve_refs_bounded(
        root,
        target,
        reference,
        depth - 1,
        target_base,
        resolver,
        context,
        state,
    );
    state.active_path.pop();
    state.active_targets.remove(&target_id);
    let resolved = resolved?;

    let nodes = before_nodes.saturating_sub(state.document.remaining_nodes);
    let bytes = before_bytes.saturating_sub(state.document.remaining_bytes);
    let value = Arc::new(resolved);
    state.memo.insert(
        key,
        MemoEntry {
            value: Arc::clone(&value),
            nodes,
            bytes,
        },
    );
    Ok(value.as_ref().clone())
}

/// Whether a schema is being compiled for request or response validation.
///
/// OpenAPI 3.0 and Swagger 2.0 apply `required` differently for `readOnly` /
/// `writeOnly` properties depending on this direction. OpenAPI 3.1+ treats
/// those keywords as JSON Schema annotations and does not inherit the 3.0 rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchemaDirection {
    Request,
    Response,
}

fn normalize_schema_for_openapi(schema: Value, version: &str, direction: SchemaDirection) -> Value {
    if version != "2.0" && !version.starts_with("3.0.") {
        // OpenAPI 3.1+: keep the schema as authored. `readOnly`/`writeOnly` are
        // JSON Schema annotations; Ferrum does not rewrite `required` here.
        return schema;
    }
    normalize_legacy_schema(schema, direction, version.starts_with("3.0."))
}

fn normalize_legacy_schema(
    schema: Value,
    direction: SchemaDirection,
    supports_write_only: bool,
) -> Value {
    match schema {
        Value::Object(mut object) => {
            let nullable = object
                .remove("nullable")
                .or_else(|| object.remove("x-nullable"))
                .and_then(|value| value.as_bool())
                .unwrap_or(false);

            if object.get("exclusiveMinimum").and_then(Value::as_bool) == Some(true) {
                if let Some(minimum) = object.get("minimum").cloned() {
                    object.insert("exclusiveMinimum".to_string(), minimum);
                    object.remove("minimum");
                }
            } else if object
                .get("exclusiveMinimum")
                .is_some_and(Value::is_boolean)
            {
                object.remove("exclusiveMinimum");
            }

            if object.get("exclusiveMaximum").and_then(Value::as_bool) == Some(true) {
                if let Some(maximum) = object.get("maximum").cloned() {
                    object.insert("exclusiveMaximum".to_string(), maximum);
                    object.remove("maximum");
                }
            } else if object
                .get("exclusiveMaximum")
                .is_some_and(Value::is_boolean)
            {
                object.remove("exclusiveMaximum");
            }

            // Filter `required` against same-object `properties` before
            // recursing so nested objects / composition members keep their
            // own direction semantics.
            apply_direction_required_semantics(&mut object, direction, supports_write_only);

            for child in object.values_mut() {
                *child =
                    normalize_legacy_schema(std::mem::take(child), direction, supports_write_only);
            }
            let value = Value::Object(object);
            if nullable {
                add_null_type(value)
            } else {
                value
            }
        }
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|child| normalize_legacy_schema(child, direction, supports_write_only))
                .collect(),
        ),
        other => other,
    }
}

/// OpenAPI 3.0 / Swagger 2.0 direction-specific `required` filtering.
///
/// - Request: a required `readOnly: true` property applies only to responses.
/// - Response: a required `writeOnly: true` property applies only to requests.
///
/// Swagger 2.0 defines `readOnly` but not `writeOnly`; response filtering is
/// therefore a no-op for Swagger documents. Property schemas without a local
/// `properties` entry (for example names satisfied only via sibling `allOf`
/// members) are left in `required` so composition is not weakened.
fn apply_direction_required_semantics(
    object: &mut Map<String, Value>,
    direction: SchemaDirection,
    supports_write_only: bool,
) {
    let Some(required) = object.get("required").and_then(Value::as_array) else {
        return;
    };
    if required.is_empty() {
        return;
    }
    let Some(properties) = object.get("properties").and_then(Value::as_object) else {
        return;
    };

    let filtered: Vec<Value> = required
        .iter()
        .filter(|name| {
            let Some(prop_name) = name.as_str() else {
                // Preserve non-string entries rather than silently dropping them.
                return true;
            };
            let Some(prop) = properties.get(prop_name).and_then(Value::as_object) else {
                return true;
            };
            match direction {
                SchemaDirection::Request => {
                    prop.get("readOnly").and_then(Value::as_bool) != Some(true)
                }
                SchemaDirection::Response if supports_write_only => {
                    prop.get("writeOnly").and_then(Value::as_bool) != Some(true)
                }
                SchemaDirection::Response => true,
            }
        })
        .cloned()
        .collect();

    if filtered.len() == required.len() {
        return;
    }
    if filtered.is_empty() {
        object.remove("required");
    } else {
        object.insert("required".to_string(), Value::Array(filtered));
    }
}

fn add_null_type(schema: Value) -> Value {
    let Value::Object(mut object) = schema else {
        return json!({ "anyOf": [schema, { "type": "null" }] });
    };
    match object.remove("type") {
        Some(Value::String(existing)) => {
            object.insert(
                "type".to_string(),
                Value::Array(vec![Value::String(existing), json!("null")]),
            );
            Value::Object(object)
        }
        Some(Value::Array(mut types)) => {
            if !types.iter().any(|value| value.as_str() == Some("null")) {
                types.push(json!("null"));
            }
            object.insert("type".to_string(), Value::Array(types));
            Value::Object(object)
        }
        Some(other) => {
            object.insert("type".to_string(), other);
            json!({ "anyOf": [Value::Object(object), { "type": "null" }] })
        }
        _ => json!({ "anyOf": [Value::Object(object), { "type": "null" }] }),
    }
}

fn path_template_to_regex(
    path_template: &str,
    literal_prefix: &str,
) -> Result<String, ExtractError> {
    // A literal route prefix must never introduce regex syntax or parameters.
    let mut regex = format!("^{}", regex::escape(literal_prefix));
    let mut literal = String::new();
    let mut chars = path_template.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '{' {
            if !literal.is_empty() {
                regex.push_str(&regex::escape(&literal));
                literal.clear();
            }
            let mut name = String::new();
            let mut closed = false;
            for inner in chars.by_ref() {
                if inner == '}' {
                    closed = true;
                    break;
                }
                name.push(inner);
            }
            if !closed || name.trim().is_empty() {
                return Err(ExtractError::MalformedExtension {
                    which: "paths",
                    error: format!("invalid OpenAPI path template '{path_template}'"),
                });
            }
            regex.push_str("[^/]+");
        } else {
            literal.push(ch);
        }
    }
    if !literal.is_empty() {
        regex.push_str(&regex::escape(&literal));
    }
    regex.push('$');
    Ok(regex)
}

/// Truncate a string at a UTF-8 character boundary so the result is ≤ `max_bytes` bytes.
fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut boundary = max_bytes.min(s.len());
    while !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    s[..boundary].to_string()
}

/// Extract Tier 1 metadata from the parsed spec root value.
///
/// Handles both Swagger 2.0 and OpenAPI 3.x.
fn extract_spec_metadata(root: &serde_json::Value, version: &str) -> ExtractedMetadata {
    let info = root.get("info");

    // description — truncated to [`MAX_SPEC_DESCRIPTION_BYTES`].
    let description = info
        .and_then(|i| i.get("description"))
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, MAX_SPEC_DESCRIPTION_BYTES));

    // contact.name / email
    // contact_name  → [`MAX_SPEC_CONTACT_NAME_BYTES`]
    // contact_email → [`MAX_SPEC_CONTACT_EMAIL_BYTES`] (RFC 5321 max)
    let contact = info.and_then(|i| i.get("contact"));
    let contact_name = contact
        .and_then(|c| c.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, MAX_SPEC_CONTACT_NAME_BYTES));
    let contact_email = contact
        .and_then(|c| c.get("email"))
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, MAX_SPEC_CONTACT_EMAIL_BYTES));

    // license.name / identifier-or-url
    let license = info.and_then(|i| i.get("license"));
    let license_name = license
        .and_then(|l| l.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, MAX_SPEC_LICENSE_NAME_BYTES));
    let license_identifier = license
        .and_then(|l| {
            // 3.1+ uses `identifier`; fallback to `url`
            l.get("identifier").or_else(|| l.get("url"))
        })
        .and_then(|v| v.as_str())
        .map(|s| truncate_utf8(s, MAX_SPEC_LICENSE_IDENTIFIER_BYTES));

    // tags — top-level `tags[].name` (both 2.0 and 3.x)
    let mut tags: Vec<String> = root
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("name"))
                .filter_map(|v| v.as_str())
                .map(|s| truncate_utf8(s, MAX_SPEC_TAG_BYTES))
                .collect()
        })
        .unwrap_or_default();
    tags.sort();
    tags.dedup();
    tags.truncate(MAX_SPEC_TAGS);

    // server_urls — bounded so metadata columns cannot eclipse the body cap.
    let server_urls = if version == "2.0" {
        // Swagger 2.0: construct from schemes[] + host + basePath
        let host = root.get("host").and_then(|v| v.as_str()).unwrap_or("");
        let base_path = root.get("basePath").and_then(|v| v.as_str()).unwrap_or("");
        if host.is_empty() {
            Vec::new()
        } else {
            let schemes: Vec<&str> = root
                .get("schemes")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|s| s.as_str()).collect())
                .unwrap_or_default();
            if schemes.is_empty() {
                Vec::new()
            } else {
                schemes
                    .iter()
                    .map(|scheme| {
                        truncate_utf8(
                            &format!("{scheme}://{host}{base_path}"),
                            MAX_SPEC_SERVER_URL_BYTES,
                        )
                    })
                    .take(MAX_SPEC_SERVER_URLS)
                    .collect()
            }
        }
    } else {
        // OpenAPI 3.x: servers[].url
        let raw: Vec<String> = root
            .get("servers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.get("url"))
                    .filter_map(|v| v.as_str())
                    .map(|s| truncate_utf8(s, MAX_SPEC_SERVER_URL_BYTES))
                    .collect()
            })
            .unwrap_or_default();
        if raw.len() > MAX_SPEC_SERVER_URLS {
            tracing::debug!(
                "extract_spec_metadata: server_urls has {} entries; truncating to {}",
                raw.len(),
                MAX_SPEC_SERVER_URLS
            );
            raw.into_iter().take(MAX_SPEC_SERVER_URLS).collect()
        } else {
            raw
        }
    };

    // operation_count — count HTTP method keys across all paths.*
    let operation_count = root
        .get("paths")
        .and_then(|v| v.as_object())
        .map(|paths| {
            paths
                .values()
                .filter_map(|path_item| path_item.as_object())
                .flat_map(|path_item| path_item.keys())
                .filter(|k| HTTP_METHODS.contains(&k.as_str()))
                .count()
                .min(u32::MAX as usize) as u32
        })
        .unwrap_or(0);

    ExtractedMetadata {
        description,
        contact_name,
        contact_email,
        license_name,
        license_identifier,
        tags,
        server_urls,
        operation_count,
    }
}

/// Compute a stable SHA-256 hex hash over the resource bundle, excluding
/// metadata fields (`api_spec_id`, `created_at`, `updated_at`).
///
/// Same bundle in → same hash out. Used by [`replace_api_spec_bundle`] to
/// skip proxy/upstream/plugin writes when only the spec document changed.
///
/// # Errors
///
/// Returns an error if any resource in the bundle cannot be serialized to JSON.
/// In practice this should never happen for a `serde_json::Value`-backed bundle,
/// but returning `Result` ensures call sites handle the failure as an internal
/// error rather than silently producing an empty hash that could trigger a false
/// hash collision.
pub fn hash_resource_bundle(bundle: &ExtractedBundle) -> Result<String, anyhow::Error> {
    let mut buf = Vec::new();

    // Proxy — strip metadata then serialize
    let proxy_json = strip_metadata(
        serde_json::to_value(&bundle.proxy)
            .map_err(|e| anyhow::anyhow!("failed to serialize proxy for resource hash: {}", e))?,
    );
    buf.extend_from_slice(&serde_json::to_vec(&proxy_json).map_err(|e| {
        anyhow::anyhow!("failed to re-serialize proxy JSON for resource hash: {}", e)
    })?);
    buf.push(b'|');

    // Upstream (optional)
    if let Some(u) = &bundle.upstream {
        let upstream_json = strip_metadata(serde_json::to_value(u).map_err(|e| {
            anyhow::anyhow!("failed to serialize upstream for resource hash: {}", e)
        })?);
        buf.extend_from_slice(&serde_json::to_vec(&upstream_json).map_err(|e| {
            anyhow::anyhow!(
                "failed to re-serialize upstream JSON for resource hash: {}",
                e
            )
        })?);
    }
    buf.push(b'|');

    // Plugins sorted by id for determinism
    let mut plugins: Vec<_> = bundle.plugins.iter().collect();
    plugins.sort_by(|a, b| a.id.cmp(&b.id));
    for p in plugins {
        let pj = strip_metadata(serde_json::to_value(p).map_err(|e| {
            anyhow::anyhow!(
                "failed to serialize plugin '{}' for resource hash: {}",
                p.id,
                e
            )
        })?);
        buf.extend_from_slice(&serde_json::to_vec(&pj).map_err(|e| {
            anyhow::anyhow!(
                "failed to re-serialize plugin JSON for resource hash: {}",
                e
            )
        })?);
        buf.push(b';');
    }

    Ok(crate::admin::spec_codec::sha256_hex(&buf))
}

/// Remove metadata-only fields from a JSON value so they don't affect the hash.
fn strip_metadata(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = v.as_object_mut() {
        obj.remove("api_spec_id");
        obj.remove("created_at");
        obj.remove("updated_at");
    }
    sort_json_value(v)
}

fn sort_json_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(obj) => {
            let mut entries: Vec<_> = obj.into_iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            serde_json::Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, sort_json_value(value)))
                    .collect(),
            )
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(sort_json_value).collect())
        }
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Determine the OpenAPI version from the root JSON value.
fn detect_version(root: &serde_json::Value) -> Result<String, ExtractError> {
    // OpenAPI 2.0 (Swagger)
    if let Some(sw) = root.get("swagger")
        && sw.as_str() == Some("2.0")
    {
        return Ok("2.0".to_string());
    }

    // OpenAPI 3.x
    if let Some(oa) = root.get("openapi")
        && let Some(s) = oa.as_str()
        && is_openapi3_version(s)
    {
        return Ok(s.to_string());
    }

    Err(ExtractError::UnknownVersion)
}

fn parse_root_document(
    body: &[u8],
    declared_format: Option<SpecFormat>,
) -> Result<(serde_json::Value, SpecFormat), ExtractError> {
    let fmt = declared_format.unwrap_or_else(|| autodetect_format(body));

    // JSON prefers serde_json so error messages mention "JSON". YAML always
    // goes through the bounded event composer (`bounded_yaml`) so anchors and
    // aliases expand under node/depth/alias-reference/byte/work budgets with
    // cycle detection — never through serde_yaml's unbounded materialization.
    //
    // Fallback: YAML flow-style documents start with `{` and look like JSON to
    // autodetect_format, but they use unquoted keys which serde_json rejects.
    // When JSON parsing fails on autodetected (not declared) input, retry as
    // YAML before surfacing the error. The YAML path applies the same budgets
    // as an explicitly declared YAML body (no autodetection differential).
    let (root, parsed_via_yaml, actual_format): (serde_json::Value, bool, SpecFormat) = match fmt {
        SpecFormat::Json => match serde_json::from_slice(body) {
            Ok(v) => (v, false, SpecFormat::Json),
            Err(e) if declared_format.is_none() => {
                // Autodetected as JSON but failed — try YAML (covers flow-style).
                // Preserve every semantic fail-closed YAML diagnostic. Only a
                // YAML syntax failure keeps the original JSON error, so adding
                // a new bounded-composer error cannot silently weaken this
                // classification through a brittle message allowlist.
                let val = crate::admin::api_specs::bounded_yaml::parse_yaml_to_json(
                    body,
                    MAX_SOURCE_DOCUMENT_NODES,
                )
                .map_err(|yaml_err| {
                    if matches!(
                        &yaml_err,
                        crate::admin::api_specs::bounded_yaml::BoundedYamlError::Parse(_)
                            | crate::admin::api_specs::bounded_yaml::BoundedYamlError::EmptyDocument
                    ) {
                        ExtractError::InvalidJson(e.to_string())
                    } else {
                        ExtractError::InvalidYaml(yaml_err.message())
                    }
                })?;
                (val, true, SpecFormat::Yaml)
            }
            Err(e) => return Err(ExtractError::InvalidJson(e.to_string())),
        },
        SpecFormat::Yaml => {
            let val = parse_yaml_document(body)?;
            (val, true, SpecFormat::Yaml)
        }
    };

    // Source-tree node cap, applied to **both** formats.
    //
    // For YAML this is defence-in-depth on top of budgeted expansion inside
    // `bounded_yaml`. For JSON it is the only structural bound besides the
    // request-body byte ceiling; without it, a JSON document could present far
    // more reference sites than an equivalently sized YAML one and face a
    // strictly weaker admission check (GHSA-8jc7-c52g-85xr).
    let mut budget = MAX_SOURCE_DOCUMENT_NODES;
    if !count_value_nodes(&root, &mut budget) {
        return Err(if parsed_via_yaml {
            ExtractError::InvalidYaml(
                "YAML document exceeds expanded node limit; reduce nesting".to_string(),
            )
        } else {
            ExtractError::InvalidJson(
                "JSON document exceeds expanded node limit; reduce nesting".to_string(),
            )
        });
    }

    Ok((root, actual_format))
}

fn parse_yaml_document(body: &[u8]) -> Result<serde_json::Value, ExtractError> {
    crate::admin::api_specs::bounded_yaml::parse_yaml_to_json(body, MAX_SOURCE_DOCUMENT_NODES)
        .map_err(|e| ExtractError::InvalidYaml(e.message()))
}

// ---------------------------------------------------------------------------
// Source-document node budget (JSON + post-expansion YAML)
// ---------------------------------------------------------------------------

/// Maximum number of `serde_json::Value` nodes allowed in a parsed source
/// document, and after a stored YAML → JSON representation conversion.
///
/// 500k nodes is generous for any real OpenAPI spec (the largest public specs
/// top out around 50k nodes). YAML anchors/aliases expand under the same cap
/// (plus depth/alias-reference/byte/work budgets) before this post-check.
pub(crate) const MAX_SOURCE_DOCUMENT_NODES: usize = 500_000;

/// Walk a `serde_json::Value` tree, decrementing `budget` for each node
/// visited.  Returns `false` (reject) when the budget hits zero.
pub(crate) fn count_value_nodes(val: &serde_json::Value, budget: &mut usize) -> bool {
    if *budget == 0 {
        return false;
    }
    *budget -= 1;
    match val {
        serde_json::Value::Array(arr) => {
            for item in arr {
                if !count_value_nodes(item, budget) {
                    return false;
                }
            }
            true
        }
        serde_json::Value::Object(map) => {
            for (_, v) in map {
                if !count_value_nodes(v, budget) {
                    return false;
                }
            }
            true
        }
        _ => true,
    }
}

/// Maximum recursion depth for [`find_forbidden_key`].
///
/// serde_yaml's own parser enforces a depth limit of ~128 for the YAML
/// document. We set an explicit, lower limit here (32) so the contract
/// is documented in code rather than relying on the parser's internal
/// behaviour.  Configs nested deeper than 32 levels are rejected with a
/// synthetic `"__depth_exceeded__"` sentinel, causing the spec to be
/// rejected at extract time (fail-closed).
const MAX_FORBIDDEN_KEY_SCAN_DEPTH: usize = 32;

/// Recursively walk a JSON value and return the first key whose name appears
/// in [`FORBIDDEN_CONFIG_KEYS`], or `None` if the value is clean.
///
/// The walk visits every level of objects and every element of arrays.
/// The walk is on the plugin's `config` VALUE only, not on the plugin
/// metadata fields (`plugin_name`, `scope`, etc.), so legitimate auth plugins
/// (`plugin_name: "jwt"`) are not falsely flagged.
///
/// Recursion is bounded by [`MAX_FORBIDDEN_KEY_SCAN_DEPTH`].  When the depth
/// limit is reached the function returns `Some("__depth_exceeded__")` so the
/// spec is rejected (fail-closed), consistent with discovering a real
/// forbidden key.
fn find_forbidden_key(value: &serde_json::Value) -> Option<&'static str> {
    find_forbidden_key_depth(value, MAX_FORBIDDEN_KEY_SCAN_DEPTH)
}

fn find_forbidden_key_for_plugin(
    plugin_name: &str,
    value: &serde_json::Value,
) -> Option<&'static str> {
    if plugin_name == "openapi_validator" {
        return find_forbidden_key_depth_for_openapi_validator(
            value,
            MAX_FORBIDDEN_KEY_SCAN_DEPTH,
            0,
        );
    }
    find_forbidden_key(value)
}

fn find_forbidden_key_depth(value: &serde_json::Value, depth: usize) -> Option<&'static str> {
    if depth == 0 {
        // Fail closed: treat excessively nested config as forbidden.
        return Some("__depth_exceeded__");
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                // Case-insensitive + trimmed match so variants like "JWT",
                // "jwt ", or NBSP-prefixed keys don't bypass the check.
                let trimmed = key.trim();
                if let Some(found) = FORBIDDEN_CONFIG_KEYS
                    .iter()
                    .find(|&&k| k.eq_ignore_ascii_case(trimmed))
                {
                    return Some(found);
                }
                // Recurse into the child value.
                if let Some(found) = find_forbidden_key_depth(child, depth - 1) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(found) = find_forbidden_key_depth(item, depth - 1) {
                    return Some(found);
                }
            }
            None
        }
        // Primitives carry no keys.
        _ => None,
    }
}

fn find_forbidden_key_depth_for_openapi_validator(
    value: &serde_json::Value,
    depth: usize,
    path_level: u8,
) -> Option<&'static str> {
    if depth == 0 {
        return Some("__depth_exceeded__");
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let trimmed = key.trim();
                let is_bypass_consumers =
                    path_level == 1 && trimmed.eq_ignore_ascii_case("consumers");
                if !is_bypass_consumers
                    && let Some(found) = FORBIDDEN_CONFIG_KEYS
                        .iter()
                        .find(|&&k| k.eq_ignore_ascii_case(trimmed))
                {
                    return Some(found);
                }
                let child_path_level = if path_level == 0 && trimmed.eq_ignore_ascii_case("bypass")
                {
                    1
                } else {
                    2
                };
                if let Some(found) = find_forbidden_key_depth_for_openapi_validator(
                    child,
                    depth - 1,
                    child_path_level,
                ) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(found) =
                    find_forbidden_key_depth_for_openapi_validator(item, depth - 1, 2)
                {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Minimal spec builders
    // -----------------------------------------------------------------------

    /// Build the smallest valid JSON spec string that has a proxy extension.
    fn minimal_json_spec(proxy_json: &str) -> String {
        format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "Test API", "version": "1.0.0"}},
                "x-ferrum-proxy": {proxy_json}
            }}"#
        )
    }

    /// Minimal proxy JSON suitable for embedding in a spec.
    fn minimal_proxy() -> &'static str {
        r#"{"id": "my-proxy", "backend_host": "api.example.com", "backend_port": 443}"#
    }

    // -----------------------------------------------------------------------
    // is_openapi3_version — SemVer parser constrained to major version 3
    // -----------------------------------------------------------------------

    #[test]
    fn is_openapi3_version_accepts_canonical_releases() {
        for v in [
            "3.0.0",
            "3.0.3",
            "3.1.0",
            "3.1.5",
            "3.2.0",
            "3.10.99",
            "3.0.123456",
        ] {
            assert!(is_openapi3_version(v), "must accept {v}");
        }
    }

    #[test]
    fn is_openapi3_version_accepts_prerelease_suffix() {
        for v in [
            "3.2.0-rc1",
            "3.1.0-alpha",
            "3.0.0-beta.2",
            "3.2.0-rc1.with.dots",
        ] {
            assert!(is_openapi3_version(v), "must accept {v}");
        }
    }

    #[test]
    fn is_openapi3_version_accepts_build_metadata() {
        for v in [
            "3.1.0+build.7",
            "3.1.0-rc.1+build.7",
            "3.2.0+exp.sha.5114f85",
            "3.0.0-alpha.1+001",
        ] {
            assert!(is_openapi3_version(v), "must accept {v}");
        }
    }

    #[test]
    fn is_openapi3_version_rejects_non_threes() {
        for v in ["2.0.0", "4.0.0", "30.0.0", "3", "3.0", "3.", ""] {
            assert!(!is_openapi3_version(v), "must reject {v:?}");
        }
    }

    #[test]
    fn is_openapi3_version_rejects_non_digit_components() {
        for v in [
            "3.x.0",
            "3.0.x",
            "3.0a.0",
            "3.0.0a",
            "3..0",
            "3.0.",
            "3.0.0-",
            "3.0.0+",
            "3.0.0-rc+",
            "3.0.0-rc+build+again",
            "3.0.0-rc..1",
            "3.0.0+build..1",
            "3.0.0-\u{0}",
            "3.-1.0",
        ] {
            assert!(!is_openapi3_version(v), "must reject {v:?}");
        }
    }

    #[test]
    fn is_openapi3_version_rejects_leading_or_trailing_whitespace() {
        // The original regex was anchored (^...$) — no whitespace allowed.
        for v in [" 3.0.0", "3.0.0 ", "\t3.0.0", "3.0.0\n"] {
            assert!(!is_openapi3_version(v), "must reject {v:?}");
        }
    }

    // -----------------------------------------------------------------------
    // Version detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_swagger_2_0() {
        let spec = minimal_json_spec(minimal_proxy());
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.version, "2.0");
    }

    #[test]
    fn test_version_openapi_3_0_3() {
        let spec = format!(
            r#"{{"openapi": "3.0.3", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.version, "3.0.3");
    }

    #[test]
    fn test_version_openapi_3_1_0() {
        let spec = format!(
            r#"{{"openapi": "3.1.0", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.version, "3.1.0");
    }

    #[test]
    fn test_version_openapi_3_2_0() {
        let spec = format!(
            r#"{{"openapi": "3.2.0", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.version, "3.2.0");
    }

    #[test]
    fn test_version_openapi_3_2_prerelease() {
        let spec = format!(
            r#"{{"openapi": "3.2.0-rc1", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.version, "3.2.0-rc1");
    }

    #[test]
    fn test_version_openapi_3_1_build_metadata() {
        let spec = format!(
            r#"{{"openapi": "3.1.0+build.7", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.version, "3.1.0+build.7");
    }

    #[test]
    fn test_version_openapi_3_1_prerelease_build_metadata() {
        let spec = format!(
            r#"{{"openapi": "3.1.0-rc.1+build.7", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.version, "3.1.0-rc.1+build.7");
    }

    #[test]
    fn test_version_missing_returns_unknown() {
        let spec = format!(
            r#"{{"info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(matches!(err, ExtractError::UnknownVersion), "got: {err}");
    }

    #[test]
    fn test_version_openapi_4_returns_unknown() {
        let spec = format!(
            r#"{{"openapi": "4.0.0", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(matches!(err, ExtractError::UnknownVersion), "got: {err}");
    }

    #[test]
    fn test_version_openapi_not_semver_returns_unknown() {
        let spec = format!(
            r#"{{"openapi": "not-a-version", "info": {{"title": "T", "version": "1"}}, "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(matches!(err, ExtractError::UnknownVersion), "got: {err}");
    }

    // -----------------------------------------------------------------------
    // Format autodetect
    // -----------------------------------------------------------------------

    #[test]
    fn test_autodetect_json_brace() {
        assert_eq!(
            autodetect_format(b"{\"openapi\": \"3.0.3\"}"),
            SpecFormat::Json
        );
    }

    #[test]
    fn test_autodetect_yaml_keyword() {
        assert_eq!(autodetect_format(b"openapi: \"3.0.3\""), SpecFormat::Yaml);
    }

    #[test]
    fn test_autodetect_json_with_leading_whitespace() {
        assert_eq!(
            autodetect_format(b"  \n  {\"swagger\": \"2.0\"}"),
            SpecFormat::Json
        );
    }

    #[test]
    fn test_autodetected_flow_style_yaml_records_yaml_format() {
        let spec = format!(
            "{{openapi: '3.1.0', info: {{title: flow, version: '1.0'}}, x-ferrum-proxy: {}}}",
            minimal_proxy()
        );

        let (_, meta) = extract(spec.as_bytes(), None, "prod").expect("flow YAML must parse");

        assert_eq!(
            meta.format,
            SpecFormat::Yaml,
            "flow-style YAML starts with '{{' and first autodetects as JSON, \
             but the YAML fallback must record the actual stored format"
        );
    }

    // -----------------------------------------------------------------------
    // Happy-path extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_minimal_json_proxy_only() {
        let spec = minimal_json_spec(minimal_proxy());
        let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
        assert_eq!(bundle.proxy.id, "my-proxy");
        assert_eq!(bundle.proxy.backend_host, "api.example.com");
        assert!(bundle.upstream.is_none());
        assert!(bundle.plugins.is_empty());
    }

    #[test]
    fn test_minimal_yaml_proxy_only() {
        let spec = r##"
swagger: "2.0"
info:
  title: "YAML Test"
  version: "2.0.0"
x-ferrum-proxy:
  id: "yaml-proxy"
  backend_host: "backend.example.com"
  backend_port: 8080
"##;
        let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Yaml), "prod").unwrap();
        assert_eq!(bundle.proxy.id, "yaml-proxy");
        assert!(bundle.upstream.is_none());
        assert!(bundle.plugins.is_empty());
    }

    #[test]
    fn test_full_bundle_proxy_upstream_plugins() {
        let spec = r##"
{
    "openapi": "3.1.0",
    "info": {"title": "Full API", "version": "3.0.0"},
    "x-ferrum-proxy": {
        "id": "full-proxy",
        "backend_host": "backend.internal",
        "backend_port": 443
    },
    "x-ferrum-upstream": {
        "id": "full-upstream",
        "targets": [
            {"host": "target1.internal", "port": 443},
            {"host": "target2.internal", "port": 443}
        ]
    },
    "x-ferrum-plugins": [
        {
            "id": "plugin-1",
            "plugin_name": "rate_limiting",
            "scope": "proxy",
            "config": {"limits": [{"scope": "default", "requests_per_minute": 100}]}
        },
        {
            "id": "plugin-2",
            "plugin_name": "cors",
            "scope": "proxy",
            "config": {"allowed_origins": ["https://example.com"]}
        }
    ]
}
"##;
        let (bundle, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
        assert_eq!(bundle.proxy.id, "full-proxy");
        assert!(bundle.upstream.is_some());
        assert_eq!(bundle.upstream.as_ref().unwrap().id, "full-upstream");
        assert_eq!(bundle.plugins.len(), 2);
        assert_eq!(bundle.plugins[0].id, "plugin-1");
        assert_eq!(bundle.plugins[1].id, "plugin-2");
        // All plugins must be proxy-scoped and linked to the proxy.
        for p in &bundle.plugins {
            assert_eq!(p.scope, PluginScope::Proxy);
            assert_eq!(p.proxy_id.as_deref(), Some("full-proxy"));
        }
        assert_eq!(meta.version, "3.1.0");
        assert_eq!(meta.title.as_deref(), Some("Full API"));
        assert_eq!(meta.info_version.as_deref(), Some("3.0.0"));
    }

    #[test]
    fn test_x_ferrum_validate_auto_injects_openapi_validator() {
        let spec = r##"
{
  "openapi": "3.0.3",
  "info": {"title": "Contract API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "contract-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  },
  "components": {
    "schemas": {
      "Order": {
        "type": "object",
        "required": ["id"],
        "properties": {
          "id": {"type": "string", "nullable": true}
        }
      }
    }
  },
  "paths": {
    "/orders/{id}": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {"$ref": "#/components/schemas/Order"}
            }
          }
        },
        "responses": {
          "200": {
            "description": "ok",
            "content": {
              "application/json": {
                "schema": {"$ref": "#/components/schemas/Order"}
              }
            }
          }
        }
      }
    }
  }
}
"##;
        let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
        assert_eq!(bundle.plugins.len(), 1);
        let plugin = &bundle.plugins[0];
        assert_eq!(plugin.plugin_name, "openapi_validator");
        assert_eq!(plugin.scope, PluginScope::Proxy);
        assert_eq!(plugin.proxy_id.as_deref(), Some("contract-proxy"));

        let operations = plugin
            .config
            .get("operations")
            .and_then(Value::as_array)
            .expect("operations array");
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0]["path_regex"], "^/orders/[^/]+$");
        assert_eq!(operations[0]["request_required"], true);
        assert_eq!(plugin.config["schema_draft"], "draft7");

        let id_type = &operations[0]["request_body"]["content"]["application/json"]["properties"]["id"]
            ["type"];
        assert_eq!(id_type, &json!(["string", "null"]));
    }

    #[test]
    fn test_x_ferrum_validate_absent_does_not_inject_validator() {
        let spec = minimal_json_spec(minimal_proxy());
        let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
        assert!(bundle.plugins.is_empty());
    }

    #[test]
    fn test_x_ferrum_validate_merges_operator_openapi_validator_config() {
        let spec = r#"
{
  "openapi": "3.1.0",
  "info": {"title": "Contract API", "version": "1.0.0"},
  "x-ferrum-validate": {
    "bypass": {"paths": ["^/health$"], "consumers": ["spec-bypass"]},
    "request": {"content_types": ["application/json", "application/problem+json"]}
  },
  "x-ferrum-proxy": {
    "id": "contract-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  },
  "x-ferrum-plugins": [{
    "id": "operator-validator",
    "plugin_name": "openapi_validator",
    "config": {
      "enforcement_mode": "log_only",
      "bypass": {"paths": ["^/ready$"], "methods": ["OPTIONS"], "consumers": ["break-glass"]},
      "operations": [{"method": "GET", "path_template": "/wrong", "path_regex": "^/wrong$"}]
    }
  }],
  "paths": {
    "/orders": {
      "post": {
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {"type": "object"}
            }
          }
        },
        "responses": {"204": {"description": "ok"}}
      }
    }
  }
}
"#;
        let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
        assert_eq!(bundle.plugins.len(), 1);
        let plugin = &bundle.plugins[0];
        assert_eq!(plugin.id, "operator-validator");
        assert_eq!(plugin.config["enforcement_mode"], "log_only");
        assert_eq!(plugin.config["schema_draft"], "draft2020-12");
        assert_eq!(plugin.config["operations"][0]["path_template"], "/orders");

        let bypass_paths = plugin.config["bypass"]["paths"].as_array().unwrap();
        assert!(bypass_paths.contains(&json!("^/health$")));
        assert!(bypass_paths.contains(&json!("^/ready$")));
        assert_eq!(plugin.config["bypass"]["methods"], json!(["OPTIONS"]));
        let bypass_consumers = plugin.config["bypass"]["consumers"].as_array().unwrap();
        assert!(bypass_consumers.contains(&json!("spec-bypass")));
        assert!(bypass_consumers.contains(&json!("break-glass")));
        assert_eq!(
            plugin.config["request_content_types"],
            json!(["application/json", "application/problem+json"])
        );
    }

    #[test]
    fn test_x_ferrum_validate_rejects_malformed_spec_bypass() {
        let spec = r#"
{
  "openapi": "3.1.0",
  "info": {"title": "Contract API", "version": "1.0.0"},
  "x-ferrum-validate": {
    "bypass": {"paths": "^/health$"}
  },
  "x-ferrum-proxy": {
    "id": "contract-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  },
  "paths": {
    "/orders": {
      "get": {
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}
"#;
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap_err();
        assert!(matches!(
            err,
            ExtractError::MalformedExtension {
                which: "x-ferrum-validate",
                ..
            }
        ));
        assert!(
            err.to_string()
                .contains("openapi_validator bypass.paths must be an array")
        );
    }

    #[test]
    fn test_x_ferrum_validate_preserves_wildcard_response_statuses() {
        let spec = r#"
{
  "openapi": "3.1.0",
  "info": {"title": "Contract API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "contract-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  },
  "paths": {
    "/orders": {
      "get": {
        "responses": {
          "4XX": {
            "description": "client error",
            "content": {
              "application/json": {
                "schema": {"type": "object", "required": ["error"]}
              }
            }
          }
        }
      }
    }
  }
}
"#;
        let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
        let plugin = &bundle.plugins[0];
        assert_eq!(
            plugin.config["operations"][0]["responses"]["4XX"]["application/json"]["required"],
            json!(["error"])
        );
    }

    #[test]
    fn test_x_ferrum_validate_rejects_external_refs() {
        let spec = r#"
{
  "openapi": "3.1.0",
  "info": {"title": "Contract API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "contract-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  },
  "paths": {
    "/orders": {
      "post": {
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {"$ref": "https://example.com/schemas/order.json"}
            }
          }
        },
        "responses": {"204": {"description": "ok"}}
      }
    }
  }
}
"#;
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap_err();
        assert!(
            matches!(err, ExtractError::UnsupportedExternalRef { .. }),
            "got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Namespace override
    // -----------------------------------------------------------------------

    #[test]
    fn test_namespace_override_ignores_spec_namespace() {
        // Spec embeds namespace "evil"; extractor must stamp "prod" instead.
        let spec = r#"{
            "swagger": "2.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "ns-proxy",
                "namespace": "evil",
                "backend_host": "be.internal",
                "backend_port": 443
            }
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap();
        assert_eq!(bundle.proxy.namespace, "prod");
    }

    // -----------------------------------------------------------------------
    // info extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_info_fields_populated() {
        let spec = minimal_json_spec(minimal_proxy());
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(meta.title.as_deref(), Some("Test API"));
        assert_eq!(meta.info_version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn test_info_fields_absent_when_no_info() {
        let spec = format!(
            r#"{{"swagger": "2.0", "x-ferrum-proxy": {}}}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert!(meta.title.is_none());
        assert!(meta.info_version.is_none());
    }

    // -----------------------------------------------------------------------
    // Rejection paths
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_x_ferrum_consumers() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-consumers": [{{"username": "alice"}}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(err, ExtractError::ConsumerExtensionNotAllowed),
            "got: {err}"
        );
    }

    #[test]
    fn test_plugin_scope_omitted_defaults_to_proxy() {
        // Matches the canonical example in docs/api_specs.md and CLAUDE.md,
        // which shows plugins WITHOUT an explicit `scope` field. The extractor
        // must default to PluginScope::Proxy rather than fail deserialization.
        let spec = format!(
            r#"{{
                "openapi": "3.1.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "rl-1",
                    "plugin_name": "rate_limiting",
                    "config": {{"limits": [{{"scope": "default", "window_seconds": 60, "max_requests": 100}}]}}
                }}]
            }}"#,
            minimal_proxy()
        );
        let (bundle, _md) = extract(spec.as_bytes(), None, "ferrum").expect("extract ok");
        assert_eq!(bundle.plugins.len(), 1);
        assert_eq!(bundle.plugins[0].scope, PluginScope::Proxy);
        assert_eq!(bundle.plugins[0].proxy_id.as_deref(), Some("my-proxy"));
    }

    #[test]
    fn test_reject_plugin_scope_global() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "bad-plugin",
                    "plugin_name": "rate_limiting",
                    "scope": "global",
                    "config": {{}}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginInvalidScope { plugin_id, scope }
                if plugin_id == "bad-plugin" && scope == "global"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_scope_proxy_group() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "grp-plugin",
                    "plugin_name": "cors",
                    "scope": "proxy_group",
                    "config": {{"allowed_origins": ["*"]}}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginInvalidScope { plugin_id, scope }
                if plugin_id == "grp-plugin" && scope == "proxy_group"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_proxy_id_mismatch() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "mismatch-plugin",
                    "plugin_name": "cors",
                    "scope": "proxy",
                    "proxy_id": "some-other-proxy",
                    "config": {{"allowed_origins": ["*"]}}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginProxyIdMismatch {
                    plugin_id,
                    plugin_proxy_id,
                    spec_proxy_id
                }
                if plugin_id == "mismatch-plugin"
                    && plugin_proxy_id == "some-other-proxy"
                    && spec_proxy_id == "my-proxy"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_duplicate_plugin_ids() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [
                    {{
                        "id": "dup-id",
                        "plugin_name": "rate_limiting",
                        "scope": "proxy",
                        "config": {{"limits": [{{"scope": "default", "requests_per_second": 10}}]}}
                    }},
                    {{
                        "id": "dup-id",
                        "plugin_name": "cors",
                        "scope": "proxy",
                        "config": {{"allowed_origins": ["*"]}}
                    }}
                ]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::MalformedExtension { which, error }
                if *which == "x-ferrum-plugins" && error.contains("duplicate plugin id")
            ),
            "duplicate plugin IDs must be rejected; got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_credentials_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "cred-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "settings": {{
                            "credentials": {{"key": "secret"}}
                        }}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "cred-plugin" && key == "credentials"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_nested_jwt_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "nested-jwt",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "auth": {{
                            "jwt": {{"secret": "abc"}}
                        }}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "nested-jwt" && key == "jwt"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_consumer_id_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "consumer-id-plugin",
                    "plugin_name": "acl",
                    "scope": "proxy",
                    "config": {{
                        "consumer_id": "alice"
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "consumer-id-plugin" && key == "consumer_id"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_missing_proxy_extension() {
        let spec = r#"{"swagger": "2.0", "info": {"title": "T", "version": "1"}}"#;
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(err, ExtractError::MissingProxyExtension),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_malformed_proxy_extension() {
        // hosts must be an array; passing a plain string triggers a serde error.
        let spec = r#"{
            "swagger": "2.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "bad",
                "backend_host": "h",
                "backend_port": 80,
                "hosts": "not-an-array"
            }
        }"#;
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                err,
                ExtractError::MalformedExtension {
                    which: "x-ferrum-proxy",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Counter-example: a `jwt` plugin with legitimate config is NOT flagged
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Fix 1: Upstream auto-link to proxy
    // -----------------------------------------------------------------------

    #[test]
    fn test_upstream_auto_links_to_proxy() {
        // Proxy has no upstream_id; extractor must set it from the upstream's id.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "link-proxy",
                "backend_host": "be.internal",
                "backend_port": 443
            },
            "x-ferrum-upstream": {
                "id": "link-upstream",
                "targets": [{"host": "t.internal", "port": 443}]
            }
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap();
        assert_eq!(
            bundle.proxy.upstream_id.as_deref(),
            Some("link-upstream"),
            "upstream_id must be auto-linked to the spec upstream's id"
        );
    }

    #[test]
    fn test_upstream_auto_link_skipped_when_proxy_already_has_matching_id() {
        // Proxy explicitly declares the same upstream_id as the spec upstream — no error.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "matching-proxy",
                "backend_host": "be.internal",
                "backend_port": 443,
                "upstream_id": "same-upstream"
            },
            "x-ferrum-upstream": {
                "id": "same-upstream",
                "targets": [{"host": "t.internal", "port": 443}]
            }
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap();
        assert_eq!(
            bundle.proxy.upstream_id.as_deref(),
            Some("same-upstream"),
            "matching explicit upstream_id must be accepted unchanged"
        );
    }

    #[test]
    fn test_upstream_link_mismatch_rejected() {
        // Proxy pinned a different upstream_id than the spec upstream's id — hard error.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "mismatch-proxy",
                "backend_host": "be.internal",
                "backend_port": 443,
                "upstream_id": "pinned-upstream"
            },
            "x-ferrum-upstream": {
                "id": "spec-upstream",
                "targets": [{"host": "t.internal", "port": 443}]
            }
        }"#;
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::ProxyUpstreamIdMismatch {
                    proxy_id,
                    proxy_upstream_id,
                    spec_upstream_id,
                }
                if proxy_id == "mismatch-proxy"
                    && proxy_upstream_id == "pinned-upstream"
                    && spec_upstream_id == "spec-upstream"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_jwt_plugin_with_legitimate_config_is_allowed() {
        // plugin_name = "jwt", but the config VALUE does not contain any
        // forbidden keys — so it must pass the forbidden-key walk.
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "jwt-plugin",
                    "plugin_name": "jwt",
                    "scope": "proxy",
                    "config": {{
                        "secret_lookup": "env",
                        "validation": {{
                            "validate_exp": true
                        }}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        // Must succeed — no error.
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(bundle.plugins.len(), 1);
        assert_eq!(bundle.plugins[0].plugin_name, "jwt");
    }

    // -----------------------------------------------------------------------
    // L2 — find_forbidden_key depth limit
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_forbidden_key_depth_limit() {
        // Build a 50-level-deep nested object whose innermost value is
        // {"keyauth": {}}.  The scan must stop at MAX_FORBIDDEN_KEY_SCAN_DEPTH (32)
        // and return Some("__depth_exceeded__"), rejecting the spec before it
        // reaches the keyauth key at depth 50.
        let mut inner = serde_json::json!({ "keyauth": {} });
        for _ in 0..50 {
            inner = serde_json::json!({ "nested": inner });
        }

        let result = find_forbidden_key(&inner);
        assert!(
            result.is_some(),
            "deeply nested config must be rejected (fail-closed)"
        );
        assert_eq!(
            result.unwrap(),
            "__depth_exceeded__",
            "depth limit must fire before finding keyauth at depth 50 \
             (limit is {})",
            MAX_FORBIDDEN_KEY_SCAN_DEPTH
        );
    }

    // -----------------------------------------------------------------------
    // Fix 1: ID assignment is deferred to the route handler (extractor
    // leaves empty IDs empty; handler calls assign_ids_for_post /
    // assign_ids_for_put). The extractor only does auto-linking with
    // whatever id values are present.
    // -----------------------------------------------------------------------

    #[test]
    fn test_proxy_id_empty_leaves_id_empty_and_plugins_stamped_to_empty() {
        // When x-ferrum-proxy.id is empty, the extractor must leave it empty
        // (ID assignment is deferred to the handler). The plugin's proxy_id
        // and the association list will also reference the empty string — the
        // handler's assign_ids_for_* call fixes these up.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "",
                "backend_host": "be.internal",
                "backend_port": 443
            },
            "x-ferrum-plugins": [
                {
                    "id": "plugin-a",
                    "plugin_name": "rate_limiting",
                    "config": {"limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]}
                }
            ]
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap();

        // proxy.id must remain empty — handler will assign it.
        assert!(
            bundle.proxy.id.is_empty(),
            "extractor must leave empty proxy.id empty"
        );

        // plugin.proxy_id must be empty (reflecting the empty proxy.id).
        assert_eq!(bundle.plugins.len(), 1);
        assert_eq!(
            bundle.plugins[0].proxy_id.as_deref(),
            Some(""),
            "plugin.proxy_id is stamped with whatever proxy.id is (empty here)"
        );

        // proxy.plugins association list must reference plugin-a
        assert_eq!(bundle.proxy.plugins.len(), 1);
        assert_eq!(bundle.proxy.plugins[0].plugin_config_id, "plugin-a");
    }

    #[test]
    fn test_upstream_id_empty_leaves_id_empty_and_proxy_upstream_id_auto_links() {
        // When x-ferrum-upstream.id is empty, the extractor leaves it empty.
        // The auto-link sets proxy.upstream_id = Some("") — handler fixes it.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "fixed-proxy",
                "backend_host": "be.internal",
                "backend_port": 443
            },
            "x-ferrum-upstream": {
                "id": "",
                "targets": [{"host": "t.internal", "port": 443}]
            }
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap();

        let upstream = bundle.upstream.as_ref().expect("upstream must be present");
        assert!(
            upstream.id.is_empty(),
            "extractor must leave empty upstream.id empty"
        );
        // Auto-link still fires: proxy.upstream_id set to the upstream's id (empty).
        assert_eq!(
            bundle.proxy.upstream_id.as_deref(),
            Some(""),
            "auto-link sets proxy.upstream_id to upstream.id even when both are empty"
        );
    }

    #[test]
    fn test_plugin_id_empty_leaves_id_empty_and_proxy_id_stamped() {
        // When a plugin entry has id = "", the extractor leaves it empty.
        // proxy_id is stamped with proxy.id (which may also be empty if not provided).
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "my-proxy",
                "backend_host": "be.internal",
                "backend_port": 443
            },
            "x-ferrum-plugins": [
                {
                    "id": "",
                    "plugin_name": "cors",
                    "config": {"allowed_origins": ["*"]}
                }
            ]
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap();

        assert_eq!(bundle.plugins.len(), 1);
        let plugin = &bundle.plugins[0];
        assert!(
            plugin.id.is_empty(),
            "extractor must leave empty plugin.id empty"
        );
        assert_eq!(
            plugin.proxy_id.as_deref(),
            Some("my-proxy"),
            "plugin.proxy_id must be stamped with proxy.id"
        );
    }

    #[test]
    fn test_invalid_proxy_id_returns_malformed_extension() {
        // An id with spaces is invalid and must return MalformedExtension.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "has spaces",
                "backend_host": "be.internal",
                "backend_port": 443
            }
        }"#;
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::MalformedExtension { which, .. }
                if *which == "x-ferrum-proxy"
            ),
            "expected MalformedExtension for x-ferrum-proxy, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Fix 2: proxy.plugins association list is populated
    // -----------------------------------------------------------------------

    #[test]
    fn test_imported_plugins_appear_in_proxy_plugins_associations() {
        // After extraction, proxy.plugins must contain PluginAssociation entries
        // for every plugin in x-ferrum-plugins, so PluginCache can instantiate them.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "assoc-proxy",
                "backend_host": "be.internal",
                "backend_port": 443
            },
            "x-ferrum-plugins": [
                {"id": "p1", "plugin_name": "rate_limiting", "config": {"limits": [{"scope": "default", "requests_per_minute": 100}]}},
                {"id": "p2", "plugin_name": "cors", "config": {"allowed_origins": ["*"]}}
            ]
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap();

        assert_eq!(bundle.plugins.len(), 2);
        assert_eq!(
            bundle.proxy.plugins.len(),
            2,
            "proxy.plugins must have one entry per imported plugin"
        );

        let assoc_ids: Vec<&str> = bundle
            .proxy
            .plugins
            .iter()
            .map(|a| a.plugin_config_id.as_str())
            .collect();
        assert!(assoc_ids.contains(&"p1"), "proxy.plugins must reference p1");
        assert!(assoc_ids.contains(&"p2"), "proxy.plugins must reference p2");
    }

    #[test]
    fn test_existing_proxy_plugins_preserved_when_importing() {
        // If the operator writes an explicit plugin association in x-ferrum-proxy.plugins
        // (e.g., pointing to a pre-existing global plugin), those entries must survive
        // and spec-extracted plugins must be added without duplication.
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "preserve-proxy",
                "backend_host": "be.internal",
                "backend_port": 443,
                "plugins": [{"plugin_config_id": "existing-global-plugin"}]
            },
            "x-ferrum-plugins": [
                {"id": "new-plugin", "plugin_name": "cors", "config": {"allowed_origins": ["*"]}}
            ]
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap();

        // Must have both the pre-existing association AND the newly imported one
        let ids: Vec<&str> = bundle
            .proxy
            .plugins
            .iter()
            .map(|a| a.plugin_config_id.as_str())
            .collect();
        assert!(
            ids.contains(&"existing-global-plugin"),
            "pre-existing association must be preserved"
        );
        assert!(
            ids.contains(&"new-plugin"),
            "newly imported plugin must be added"
        );
        assert_eq!(ids.len(), 2, "no duplicates");
    }

    // -----------------------------------------------------------------------
    // M1 — Tag name validation (reject forbidden SQL LIKE characters)
    // -----------------------------------------------------------------------

    fn spec_with_tag(tag: &str) -> String {
        format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "tags": [{{"name": "{tag}"}}],
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        )
    }

    #[test]
    fn test_tag_with_percent_rejected() {
        let spec = spec_with_tag("foo%bar");
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidTagName { name, char: '%' } if name == "foo%bar"),
            "expected InvalidTagName for '%'; got: {err}"
        );
    }

    #[test]
    fn test_tag_with_quote_rejected() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "tags": [{{"name": "foo\"bar"}}],
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidTagName { char: '"', .. }),
            "expected InvalidTagName for '\"'; got: {err}"
        );
    }

    #[test]
    fn test_tag_with_backslash_rejected() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "tags": [{{"name": "foo\\\\bar"}}],
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidTagName { char: '\\', .. }),
            "expected InvalidTagName for '\\\\'; got: {err}"
        );
    }

    /// `_` is the SQL LIKE single-character wildcard — without rejecting it,
    /// `?has_tag=api_v1` would falsely match `apixv1`.
    #[test]
    fn test_tag_with_underscore_rejected() {
        let spec = spec_with_tag("api_v1");
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidTagName { name, char: '_' } if name == "api_v1"),
            "expected InvalidTagName for '_'; got: {err}"
        );
    }

    #[test]
    fn test_tag_with_normal_chars_accepted() {
        let spec = spec_with_tag("my-tag-v1.0");
        // Must not error. Note: `_` is NOT in the allowed set (see
        // test_tag_with_underscore_rejected).
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum")
            .expect("tag with normal chars must be accepted");
        assert!(meta.tags.contains(&"my-tag-v1.0".to_string()));
    }

    // -----------------------------------------------------------------------
    // L3 — title and info_version truncation
    // -----------------------------------------------------------------------

    #[test]
    fn test_title_truncated_to_1024_bytes() {
        // Construct a title that is 2048 ASCII characters long.
        let long_title: String = "A".repeat(2048);
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "{long_title}", "version": "1.0"}},
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum")
            .expect("extract with long title must succeed");
        let title = meta.title.expect("title must be present");
        assert_eq!(
            title.len(),
            1024,
            "title must be truncated to 1024 bytes; got {} bytes",
            title.len()
        );
    }

    #[test]
    fn test_info_version_truncated_to_256_bytes() {
        // Construct a version string that is 1024 ASCII characters long.
        let long_ver: String = "1".repeat(1024);
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "{long_ver}"}},
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "ferrum")
            .expect("extract with long info_version must succeed");
        let iv = meta.info_version.expect("info_version must be present");
        assert_eq!(
            iv.len(),
            256,
            "info_version must be truncated to 256 bytes; got {} bytes",
            iv.len()
        );
    }

    // -----------------------------------------------------------------------
    // Item 4 — Tier 1 metadata field truncation tests
    // -----------------------------------------------------------------------

    fn spec_with_info_contact_license(
        contact_name: &str,
        contact_email: &str,
        license_name: &str,
        license_id: &str,
    ) -> String {
        format!(
            r#"{{
                "swagger": "2.0",
                "info": {{
                    "title": "T", "version": "1",
                    "contact": {{"name": "{contact_name}", "email": "{contact_email}"}},
                    "license": {{"name": "{license_name}", "identifier": "{license_id}"}}
                }},
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        )
    }

    #[test]
    fn test_contact_name_truncated() {
        let long_name: String = "N".repeat(512);
        let spec = spec_with_info_contact_license(&long_name, "a@b.com", "MIT", "MIT");
        let meta = extract_spec_metadata(
            &serde_json::from_str::<serde_json::Value>(&spec).unwrap(),
            "2.0",
        );
        let name = meta.contact_name.expect("contact_name must be present");
        assert_eq!(
            name.len(),
            256,
            "contact_name must be truncated to 256 bytes; got {}",
            name.len()
        );
    }

    #[test]
    fn test_contact_email_truncated() {
        let long_email: String = "e".repeat(500) + "@example.com";
        let spec = spec_with_info_contact_license("Alice", &long_email, "MIT", "MIT");
        let meta = extract_spec_metadata(
            &serde_json::from_str::<serde_json::Value>(&spec).unwrap(),
            "2.0",
        );
        let email = meta.contact_email.expect("contact_email must be present");
        assert_eq!(
            email.len(),
            320,
            "contact_email must be truncated to 320 bytes; got {}",
            email.len()
        );
    }

    #[test]
    fn test_license_name_truncated() {
        let long_name: String = "L".repeat(512);
        let spec = spec_with_info_contact_license("Alice", "a@b.com", &long_name, "MIT");
        let meta = extract_spec_metadata(
            &serde_json::from_str::<serde_json::Value>(&spec).unwrap(),
            "2.0",
        );
        let lname = meta.license_name.expect("license_name must be present");
        assert_eq!(
            lname.len(),
            256,
            "license_name must be truncated to 256 bytes; got {}",
            lname.len()
        );
    }

    #[test]
    fn test_license_identifier_truncated() {
        let long_id: String = "X".repeat(512);
        let spec = spec_with_info_contact_license("Alice", "a@b.com", "MIT", &long_id);
        let meta = extract_spec_metadata(
            &serde_json::from_str::<serde_json::Value>(&spec).unwrap(),
            "2.0",
        );
        let lid = meta
            .license_identifier
            .expect("license_identifier must be present");
        assert_eq!(
            lid.len(),
            128,
            "license_identifier must be truncated to 128 bytes; got {}",
            lid.len()
        );
    }

    #[test]
    fn test_server_url_individual_truncated() {
        // A single very long server URL must be truncated at 2048 bytes.
        let long_url: String = format!("https://example.com/{}", "p".repeat(4000));
        let spec = format!(
            r#"{{
                "openapi": "3.1.0",
                "info": {{"title": "T", "version": "1"}},
                "servers": [{{"url": "{long_url}"}}],
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let meta = extract_spec_metadata(
            &serde_json::from_str::<serde_json::Value>(&spec).unwrap(),
            "3.1.0",
        );
        assert_eq!(meta.server_urls.len(), 1, "must have one server URL");
        assert_eq!(
            meta.server_urls[0].len(),
            2048,
            "server URL must be truncated to 2048 bytes; got {}",
            meta.server_urls[0].len()
        );
    }

    #[test]
    fn test_server_urls_cardinality_capped() {
        // Build 50 distinct server URLs — only the first 32 should survive.
        let urls: String = (0..50)
            .map(|i| format!("{{\"url\": \"https://server-{i}.example.com\"}}"))
            .collect::<Vec<_>>()
            .join(", ");
        let spec = format!(
            r#"{{
                "openapi": "3.1.0",
                "info": {{"title": "T", "version": "1"}},
                "servers": [{urls}],
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let meta = extract_spec_metadata(
            &serde_json::from_str::<serde_json::Value>(&spec).unwrap(),
            "3.1.0",
        );
        assert_eq!(
            meta.server_urls.len(),
            32,
            "server_urls must be capped at 32 entries; got {}",
            meta.server_urls.len()
        );
    }

    // -----------------------------------------------------------------------
    // YAML bounded anchor/alias expansion
    // -----------------------------------------------------------------------

    #[test]
    fn count_value_nodes_within_budget() {
        let val: serde_json::Value = serde_json::from_str(r#"{"a": [1, 2, {"b": 3}]}"#).unwrap();
        let mut budget: usize = 100;
        assert!(count_value_nodes(&val, &mut budget));
        // root object + "a" array + 1 + 2 + inner object + 3 = 6 nodes
        assert_eq!(budget, 94);
    }

    #[test]
    fn count_value_nodes_exceeds_budget() {
        let val: serde_json::Value = serde_json::from_str(r#"[1, 2, 3, 4, 5]"#).unwrap();
        let mut budget: usize = 3;
        assert!(!count_value_nodes(&val, &mut budget));
    }

    #[test]
    fn yaml_anchor_and_alias_expand_deterministically() {
        let yaml = concat!(
            "openapi: '3.1.0'\n",
            "info: &info\n",
            "  title: Anchored\n",
            "  version: '1.0'\n",
            "x-ferrum-proxy:\n",
            "  id: test\n",
            "  backend_host: x.com\n",
            "  backend_port: 443\n",
            "components:\n",
            "  schemas:\n",
            "    Reused: *info\n",
        );
        let (bundle, meta) = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "default").unwrap();
        assert_eq!(bundle.proxy.id, "test");
        assert_eq!(meta.title.as_deref(), Some("Anchored"));
    }

    #[test]
    fn yaml_alias_chain_expands() {
        let yaml = concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: Chain\n",
            "  version: '1.0'\n",
            "x-ferrum-proxy: &proxy\n",
            "  id: test\n",
            "  backend_host: x.com\n",
            "  backend_port: 443\n",
            "paths: {}\n",
            "x-copy: *proxy\n",
        );
        let (bundle, _) = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "default").unwrap();
        assert_eq!(bundle.proxy.id, "test");
    }

    #[test]
    fn flow_style_yaml_anchor_expands_on_json_fallback() {
        let yaml = b"{openapi: '3.1.0', info: &info {title: flow, version: '1.0'}, \
                     x-ferrum-proxy: {id: test, backend_host: x.com, backend_port: 443}, \
                     reused: *info}";
        let (bundle, meta) = extract(yaml, None, "default").unwrap();
        assert_eq!(bundle.proxy.id, "test");
        assert_eq!(meta.title.as_deref(), Some("flow"));
    }

    #[test]
    fn yaml_anchor_like_text_in_quotes_and_comments_allowed() {
        let yaml = concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: \"R&D *literal*\"\n",
            "  version: '1.0'\n",
            "  description: 'quoted &anchor and *alias text'\n",
            "# comment mentions &anchor and *alias\n",
            "x-ferrum-proxy: {id: test, backend_host: x.com, backend_port: 443}",
        )
        .as_bytes();
        let (bundle, _meta) = extract(yaml, Some(SpecFormat::Yaml), "default").unwrap();
        assert_eq!(bundle.proxy.id, "test");
    }

    #[test]
    fn yaml_anchor_like_text_in_plain_scalars_allowed() {
        let yaml = concat!(
            "openapi: 3.1.0\n",
            "info:\n",
            "  title: Terms & Conditions\n",
            "  version: 1.0\n",
            "  description: Use *bold* text and https://example.com?a=1&b=2 literally.\n",
            "servers:\n",
            "  - url: https://example.com?a=1&b=2\n",
            "x-ferrum-proxy:\n",
            "  id: test\n",
            "  backend_host: x.com\n",
            "  backend_port: 443",
        )
        .as_bytes();
        let (bundle, meta) = extract(yaml, Some(SpecFormat::Yaml), "default").unwrap();
        assert_eq!(bundle.proxy.id, "test");
        assert_eq!(meta.title.as_deref(), Some("Terms & Conditions"));
        assert!(
            meta.description
                .as_deref()
                .is_some_and(|desc| desc.contains("*bold*"))
        );
        assert_eq!(
            meta.server_urls,
            vec!["https://example.com?a=1&b=2".to_string()]
        );
    }

    #[test]
    fn yaml_anchor_like_text_in_block_scalars_allowed() {
        let yaml = concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: Block Scalars\n",
            "  version: '1.0'\n",
            "  description: |\n",
            "    Use *bold* text in Markdown.\n",
            "    HTML entity text like &copy; is literal here.\n",
            "x-ferrum-proxy:\n",
            "  id: test\n",
            "  backend_host: x.com\n",
            "  backend_port: 443",
        )
        .as_bytes();
        let (bundle, meta) = extract(yaml, Some(SpecFormat::Yaml), "default").unwrap();
        assert_eq!(bundle.proxy.id, "test");
        assert!(
            meta.description
                .as_deref()
                .is_some_and(|desc| desc.contains("*bold*"))
        );
    }

    #[test]
    fn yaml_anchor_after_block_scalar_still_expands() {
        let yaml = concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: Block Scalars\n",
            "  version: '1.0'\n",
            "  description: >-\n",
            "    Folded *literal* text is fine.\n",
            "servers: &servers\n",
            "  - url: https://example.com\n",
            "x-ferrum-proxy: {id: test, backend_host: x.com, backend_port: 443}\n",
            "copied: *servers\n",
        )
        .as_bytes();
        let (bundle, meta) = extract(yaml, Some(SpecFormat::Yaml), "default").unwrap();
        assert_eq!(bundle.proxy.id, "test");
        assert_eq!(meta.server_urls, vec!["https://example.com".to_string()]);
    }

    #[test]
    fn yaml_alias_bomb_rejected_by_budget() {
        // Deeply nested anchors that expand exponentially must fail closed
        // under node/work budgets before unbounded allocation.
        let yaml = b"a: &a [1,2,3,4,5,6,7,8]\n\
                      b: &b [*a,*a,*a,*a,*a,*a,*a,*a]\n\
                      c: &c [*b,*b,*b,*b,*b,*b,*b,*b]\n\
                      d: &d [*c,*c,*c,*c,*c,*c,*c,*c]\n\
                      e: &e [*d,*d,*d,*d,*d,*d,*d,*d]\n\
                      f: &f [*e,*e,*e,*e,*e,*e,*e,*e]\n\
                      g: &g [*f,*f,*f,*f,*f,*f,*f,*f]\n\
                      openapi: '3.0.0'\n\
                      info: {title: bomb, version: '1.0'}\n\
                      x-ferrum-proxy: {id: test, backend_host: x.com, backend_port: 443}";
        let err = extract(yaml, Some(SpecFormat::Yaml), "default").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::InvalidYaml(msg)
                    if msg.contains("node limit")
                        || msg.contains("work limit")
                        || msg.contains("alias reference")
                        || msg.contains("byte limit")
            ),
            "alias bomb must be rejected by expansion budgets, got {err:?}"
        );
    }

    #[test]
    fn yaml_undefined_alias_rejected() {
        let yaml = b"openapi: '3.1.0'\n\
                     info: *missing\n\
                     x-ferrum-proxy: {id: test, backend_host: x.com, backend_port: 443}";
        let err = extract(yaml, Some(SpecFormat::Yaml), "default").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidYaml(msg) if msg.contains("undefined YAML alias")),
            "expected undefined alias rejection, got {err:?}"
        );
    }

    #[test]
    fn yaml_alias_cycle_rejected() {
        // Use concat! (not `\` line continuations): Rust elides indentation after
        // `\`-newline, which flattens the mapping and drops the self-ref cycle.
        let yaml = concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: Cycle\n",
            "  version: '1.0'\n",
            "loop: &a\n",
            "  self: *a\n",
            "x-ferrum-proxy: {id: test, backend_host: x.com, backend_port: 443}\n",
        );
        let err = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "default").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidYaml(msg) if msg.contains("cycle")),
            "expected alias cycle rejection, got {err:?}"
        );
    }

    #[test]
    fn yaml_anchored_scalar_title_preserved() {
        let yaml = concat!(
            "openapi: '3.1.0'\n",
            "info:\n",
            "  title: &title Alias Scalar\n",
            "  version: '1.0'\n",
            "components:\n",
            "  schemas:\n",
            "    Shared:\n",
            "      type: string\n",
            "      default: *title\n",
            "x-ferrum-proxy: {id: test, backend_host: x.com, backend_port: 443}\n",
        );
        let (bundle, meta) = extract(yaml.as_bytes(), Some(SpecFormat::Yaml), "default").unwrap();
        assert_eq!(bundle.proxy.id, "test");
        assert_eq!(meta.title.as_deref(), Some("Alias Scalar"));
    }

    #[test]
    fn autodetected_flow_yaml_duplicate_key_is_invalid_yaml() {
        let yaml = br#"{openapi: '3.1.0', info: {title: Duplicate, version: '1.0'}, x-ferrum-proxy: {id: test, backend_host: x.com, backend_port: 443}, marker: one, marker: two}"#;
        let err = extract(yaml, None, "default").unwrap_err();
        assert!(
            matches!(&err, ExtractError::InvalidYaml(msg) if msg.contains("duplicate key")),
            "semantic YAML failures must survive JSON-first autodetection, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Spec without x-ferrum-consumers passes (positive control)
    // -----------------------------------------------------------------------

    #[test]
    fn test_spec_without_consumers_extension_passes() {
        let spec = minimal_json_spec(minimal_proxy());
        let result = extract(spec.as_bytes(), Some(SpecFormat::Json), "test");
        assert!(
            result.is_ok(),
            "spec without x-ferrum-consumers must pass; got: {:?}",
            result.unwrap_err()
        );
    }

    // -----------------------------------------------------------------------
    // Plugin with matching proxy_id accepted
    // -----------------------------------------------------------------------

    #[test]
    fn test_plugin_with_matching_proxy_id_accepted() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "matching-plugin",
                    "plugin_name": "cors",
                    "scope": "proxy",
                    "proxy_id": "my-proxy",
                    "config": {{"allowed_origins": ["*"]}}
                }}]
            }}"#,
            minimal_proxy()
        );
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test")
            .expect("plugin with matching proxy_id must be accepted");
        assert_eq!(bundle.plugins.len(), 1);
        assert_eq!(bundle.plugins[0].proxy_id.as_deref(), Some("my-proxy"));
    }

    // -----------------------------------------------------------------------
    // Credential key detection — all FORBIDDEN_CONFIG_KEYS
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_plugin_config_with_keyauth_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "keyauth-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "keyauth": {{"key": "abc123"}}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "keyauth-plugin" && key == "keyauth"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_basicauth_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "basicauth-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "basicauth": {{"username": "admin", "password": "pass"}}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "basicauth-plugin" && key == "basicauth"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_hmac_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "hmac-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "hmac": {{"secret": "s3cret"}}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "hmac-plugin" && key == "hmac"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_mtls_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "mtls-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "mtls": {{"cert_path": "/path/to/cert"}}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "mtls-plugin" && key == "mtls"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_consumer_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "consumer-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "consumer": {{"id": "alice"}}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "consumer-plugin" && key == "consumer"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_consumer_groups_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "groups-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "consumer_groups": ["admins"]
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "groups-plugin" && key == "consumer_groups"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_reject_plugin_config_with_consumers_key() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "consumers-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "consumers": ["alice", "bob"]
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "consumers-plugin" && key == "consumers"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_credential_key_detection_is_case_insensitive() {
        // Upper-case "JWT" in config key must still be caught.
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "case-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "JWT": {{"secret": "abc"}}
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "case-plugin" && key == "jwt"
            ),
            "case-insensitive credential key detection must catch 'JWT'; got: {err}"
        );
    }

    #[test]
    fn test_credential_key_in_array_element_detected() {
        // Forbidden key nested inside an array element must be caught.
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "arr-plugin",
                    "plugin_name": "custom",
                    "scope": "proxy",
                    "config": {{
                        "rules": [
                            {{"keyauth": {{"key": "secret"}}}}
                        ]
                    }}
                }}]
            }}"#,
            minimal_proxy()
        );
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(
                &err,
                ExtractError::PluginContainsCredentials { plugin_id, key }
                if plugin_id == "arr-plugin" && key == "keyauth"
            ),
            "forbidden key inside array element must be detected; got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // find_forbidden_key — clean configs pass
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_forbidden_key_returns_none_for_clean_config() {
        let config = serde_json::json!({
            "window_size": 60,
            "window_count": 100,
            "nested": {
                "deep": {
                    "setting": true
                }
            }
        });
        assert!(
            find_forbidden_key(&config).is_none(),
            "clean config must not trigger forbidden key detection"
        );
    }

    #[test]
    fn test_find_forbidden_key_returns_none_for_primitive_values() {
        assert!(find_forbidden_key(&serde_json::json!(42)).is_none());
        assert!(find_forbidden_key(&serde_json::json!("hello")).is_none());
        assert!(find_forbidden_key(&serde_json::json!(true)).is_none());
        assert!(find_forbidden_key(&serde_json::json!(null)).is_none());
    }

    // -----------------------------------------------------------------------
    // Tag validation — empty tag name
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_tag_name_accepted() {
        // Empty strings don't contain forbidden characters, so they pass
        // the tag validation. The tag array is de-duplicated and sorted, so
        // a single empty tag survives as [""].
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "tags": [{{"name": ""}}],
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let result = extract(spec.as_bytes(), Some(SpecFormat::Json), "test");
        assert!(
            result.is_ok(),
            "empty tag name must be accepted; got: {:?}",
            result.unwrap_err()
        );
    }

    // -----------------------------------------------------------------------
    // hash_resource_bundle — determinism and metadata-independence
    // -----------------------------------------------------------------------

    fn build_test_bundle(proxy_id: &str, api_spec_id: Option<&str>) -> ExtractedBundle {
        let spec = format!(
            r#"{{
                "openapi": "3.1.0",
                "info": {{"title": "Hash Test", "version": "1"}},
                "x-ferrum-proxy": {{
                    "id": "{proxy_id}",
                    "backend_host": "be.internal",
                    "backend_port": 443
                }},
                "x-ferrum-upstream": {{
                    "id": "hash-upstream",
                    "targets": [{{"host": "t.internal", "port": 443}}]
                }},
                "x-ferrum-plugins": [{{
                    "id": "hash-plugin",
                    "plugin_name": "cors",
                    "scope": "proxy",
                    "config": {{"allowed_origins": ["https://example.com"]}}
                }}]
            }}"#
        );
        let (mut bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();

        // Stamp api_spec_id if requested (simulating post-extraction handler behavior).
        if let Some(spec_id) = api_spec_id {
            bundle.proxy.api_spec_id = Some(spec_id.to_string());
            if let Some(ref mut u) = bundle.upstream {
                u.api_spec_id = Some(spec_id.to_string());
            }
            for p in &mut bundle.plugins {
                p.api_spec_id = Some(spec_id.to_string());
            }
        }

        bundle
    }

    #[test]
    fn test_hash_same_resources_produces_same_hash() {
        let bundle1 = build_test_bundle("hash-proxy", None);
        let bundle2 = build_test_bundle("hash-proxy", None);

        let hash1 = hash_resource_bundle(&bundle1).unwrap();
        let hash2 = hash_resource_bundle(&bundle2).unwrap();

        assert_eq!(hash1, hash2, "identical bundles must produce the same hash");
    }

    #[test]
    fn test_hash_different_resources_produces_different_hash() {
        let bundle1 = build_test_bundle("hash-proxy-a", None);
        let bundle2 = build_test_bundle("hash-proxy-b", None);

        let hash1 = hash_resource_bundle(&bundle1).unwrap();
        let hash2 = hash_resource_bundle(&bundle2).unwrap();

        assert_ne!(
            hash1, hash2,
            "different proxy IDs must produce different hashes"
        );
    }

    #[test]
    fn test_hash_ignores_api_spec_id() {
        let bundle_without = build_test_bundle("hash-proxy", None);
        let bundle_with_a = build_test_bundle("hash-proxy", Some("spec-aaa"));
        let bundle_with_b = build_test_bundle("hash-proxy", Some("spec-bbb"));

        let hash_without = hash_resource_bundle(&bundle_without).unwrap();
        let hash_a = hash_resource_bundle(&bundle_with_a).unwrap();
        let hash_b = hash_resource_bundle(&bundle_with_b).unwrap();

        assert_eq!(
            hash_without, hash_a,
            "api_spec_id must not affect resource hash"
        );
        assert_eq!(
            hash_a, hash_b,
            "different api_spec_id values must produce the same hash"
        );
    }

    #[test]
    fn test_hash_ignores_created_at_and_updated_at() {
        use chrono::{TimeZone, Utc};

        let mut bundle1 = build_test_bundle("hash-proxy", None);
        let mut bundle2 = build_test_bundle("hash-proxy", None);

        // Stamp different timestamps — hash_resource_bundle strips
        // created_at / updated_at via strip_metadata, so these must not
        // affect the hash.
        bundle1.proxy.created_at = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        bundle1.proxy.updated_at = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        bundle2.proxy.created_at = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        bundle2.proxy.updated_at = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

        let hash1 = hash_resource_bundle(&bundle1).unwrap();
        let hash2 = hash_resource_bundle(&bundle2).unwrap();

        assert_eq!(
            hash1, hash2,
            "different created_at/updated_at must not affect resource hash"
        );
    }

    #[test]
    fn test_hash_is_valid_hex_sha256() {
        let bundle = build_test_bundle("hash-proxy", None);
        let hash = hash_resource_bundle(&bundle).unwrap();

        // SHA-256 hex digest is exactly 64 hex characters.
        assert_eq!(
            hash.len(),
            64,
            "hash must be 64 hex chars; got {}",
            hash.len()
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be valid hex; got: {hash}"
        );
    }

    #[test]
    fn test_hash_without_upstream_differs_from_with_upstream() {
        let bundle_with = build_test_bundle("hash-proxy", None);

        // Build a bundle without upstream.
        let spec_no_upstream = r#"{
            "openapi": "3.1.0",
            "info": {"title": "Hash Test", "version": "1"},
            "x-ferrum-proxy": {
                "id": "hash-proxy",
                "backend_host": "be.internal",
                "backend_port": 443
            },
            "x-ferrum-plugins": [{
                "id": "hash-plugin",
                "plugin_name": "cors",
                "scope": "proxy",
                "config": {"allowed_origins": ["https://example.com"]}
            }]
        }"#;
        let (bundle_without, _) =
            extract(spec_no_upstream.as_bytes(), Some(SpecFormat::Json), "test").unwrap();

        let hash_with = hash_resource_bundle(&bundle_with).unwrap();
        let hash_without = hash_resource_bundle(&bundle_without).unwrap();

        assert_ne!(
            hash_with, hash_without,
            "bundle with upstream must hash differently from bundle without"
        );
    }

    // -----------------------------------------------------------------------
    // Basic extraction: doc missing x-ferrum-proxy
    // -----------------------------------------------------------------------

    #[test]
    fn test_doc_missing_proxy_extension_returns_error() {
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "No Proxy", "version": "1"},
            "x-ferrum-upstream": {
                "id": "orphan-upstream",
                "targets": [{"host": "t.internal", "port": 443}]
            }
        }"#;
        let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap_err();
        assert!(
            matches!(err, ExtractError::MissingProxyExtension),
            "got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Basic extraction: doc with only x-ferrum-upstream extracts upstream
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_upstream_sets_namespace() {
        let spec = r#"{
            "openapi": "3.1.0",
            "info": {"title": "T", "version": "1"},
            "x-ferrum-proxy": {
                "id": "up-ns-proxy",
                "backend_host": "be.internal",
                "backend_port": 443
            },
            "x-ferrum-upstream": {
                "id": "up-ns-upstream",
                "targets": [{"host": "t.internal", "port": 443}]
            }
        }"#;
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "custom-ns").unwrap();
        let upstream = bundle.upstream.as_ref().expect("upstream must be present");
        assert_eq!(
            upstream.namespace, "custom-ns",
            "upstream namespace must be overridden to the caller's namespace"
        );
    }

    // -----------------------------------------------------------------------
    // Basic extraction: plugins get namespace stamped
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_plugins_get_namespace_stamped() {
        let spec = format!(
            r#"{{
                "swagger": "2.0",
                "info": {{"title": "T", "version": "1"}},
                "x-ferrum-proxy": {},
                "x-ferrum-plugins": [{{
                    "id": "ns-plugin",
                    "plugin_name": "cors",
                    "scope": "proxy",
                    "config": {{"allowed_origins": ["*"]}}
                }}]
            }}"#,
            minimal_proxy()
        );
        let (bundle, _) = extract(spec.as_bytes(), Some(SpecFormat::Json), "my-namespace").unwrap();
        assert_eq!(bundle.plugins.len(), 1);
        assert_eq!(
            bundle.plugins[0].namespace, "my-namespace",
            "plugin namespace must be stamped with the caller's namespace"
        );
    }

    // -----------------------------------------------------------------------
    // Operation count extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_operation_count_from_paths() {
        let spec = format!(
            r#"{{
                "openapi": "3.1.0",
                "info": {{"title": "T", "version": "1"}},
                "paths": {{
                    "/users": {{
                        "get": {{"summary": "List users"}},
                        "post": {{"summary": "Create user"}}
                    }},
                    "/users/{{id}}": {{
                        "get": {{"summary": "Get user"}},
                        "put": {{"summary": "Update user"}},
                        "delete": {{"summary": "Delete user"}}
                    }}
                }},
                "x-ferrum-proxy": {}
            }}"#,
            minimal_proxy()
        );
        let (_, meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "test").unwrap();
        assert_eq!(
            meta.operation_count, 5,
            "operation_count must be 5 (2 + 3 HTTP methods); got {}",
            meta.operation_count
        );
    }
}
