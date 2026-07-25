//! TLS material inventory collection.
//!
//! The admin API and Prometheus scrape path both use this module to enumerate
//! configured TLS sources without exposing private key bytes. Certificate-like
//! material is parsed for operator metadata; private keys are only checked for
//! parseability and are never fingerprinted in responses or metrics.
//!
//! Collection performs real source I/O (filesystem, Kubernetes, cloud secret
//! managers) and therefore never runs on a request path. Two scopes exist:
//!
//! - [`TlsInventory::collect`] — the full operator inventory behind
//!   `GET /admin/tls/inventory`, an explicit authenticated request. It loads
//!   every configured source, including private keys, which are parse-checked
//!   and immediately dropped.
//! - [`TlsInventory::collect_public_metadata`] — the metrics-safe scope used by
//!   the bounded background refresh behind
//!   [`crate::tls::inventory_cache`]. It loads only public
//!   certificate-family material (certificates, CA bundles, CRLs) and **never**
//!   materializes private-key, JWKS, or OCSP bytes: those entries report health
//!   from the owning validated config/reload state instead (issue #2410).
//!
//! `/metrics` itself only ever reads the cached snapshot
//! ([`crate::tls::inventory_cache::snapshot`]) and performs zero source I/O.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

use crate::config::EnvConfig;
use crate::config::types::{GatewayConfig, PluginConfig};
use crate::tls::source::subscription::source_is_refreshable;
use crate::tls::source::{
    CertSource, MaterialError, MaterialKind, SourceScheme, load_material_blocking,
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsInventoryState {
    Loaded,
    Unsupported,
    Unavailable,
    Invalid,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsInventorySource {
    pub kind: String,
    pub identifier: String,
    pub refreshable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct TlsInventoryUsage {
    pub surface: String,
    pub role: String,
    pub resource_type: String,
    pub resource_id: String,
    pub field: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsInventoryEntry {
    pub id: String,
    pub material_kind: String,
    pub source: TlsInventorySource,
    pub state: TlsInventoryState,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub used_by: Vec<TlsInventoryUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sans: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_until_expiry: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TlsInventory {
    pub entries: Vec<TlsInventoryEntry>,
}

/// How much of each configured source an inventory collection may materialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryScope {
    /// Load every configured source. Private keys are parse-checked and
    /// dropped; JWKS/OCSP material is fetched so an unreadable source is
    /// reported as such. Used by the authenticated operator inventory endpoint.
    Full,
    /// Load only public certificate-family material (certificate, CA bundle,
    /// CRL). Private-key, JWKS, and OCSP sources are never materialized; their
    /// state comes from the owning validated config/reload state. Used by the
    /// cached snapshot that backs certificate metrics.
    PublicMetadata,
}

impl InventoryScope {
    /// Whether this scope may load `kind` from its configured source.
    ///
    /// Only certificate-family material yields public metadata the inventory
    /// actually renders (subject/issuer/SANs/validity/fingerprint/CRL counts),
    /// so the metrics scope loads nothing else — in particular never a private
    /// key, which would let a scraper drive key materialization outside the TLS
    /// reload lifecycle.
    fn may_load(self, kind: MaterialKind) -> bool {
        match self {
            Self::Full => true,
            Self::PublicMetadata => matches!(
                kind,
                MaterialKind::Cert | MaterialKind::CaBundle | MaterialKind::Crl
            ),
        }
    }
}

#[derive(Debug, Clone)]
struct InventorySourceRef {
    source: CertSource,
    kind: MaterialKind,
    usage: TlsInventoryUsage,
}

#[derive(Debug, Clone, Copy)]
struct ResourceUsageRef<'a> {
    surface: &'static str,
    role: &'static str,
    resource_type: &'static str,
    resource_id: &'a str,
    field: &'static str,
}

#[derive(Debug)]
struct InventoryEntryBuilder {
    id: String,
    source: CertSource,
    kind: MaterialKind,
    usages: BTreeSet<TlsInventoryUsage>,
}

impl TlsInventory {
    /// Full operator inventory. Loads every configured source, including
    /// private keys. Blocking; never call from a request path.
    pub fn collect(env_config: Option<&EnvConfig>, gateway_config: Option<&GatewayConfig>) -> Self {
        Self::collect_with_scope(env_config, gateway_config, InventoryScope::Full)
    }

    /// Metrics-safe inventory. Loads only public certificate-family material
    /// and never materializes private-key bytes. Blocking; runs on the bounded
    /// background refresh in [`crate::tls::inventory_cache`], never on a
    /// request path.
    pub fn collect_public_metadata(
        env_config: Option<&EnvConfig>,
        gateway_config: Option<&GatewayConfig>,
    ) -> Self {
        Self::collect_with_scope(env_config, gateway_config, InventoryScope::PublicMetadata)
    }

    pub fn collect_with_scope(
        env_config: Option<&EnvConfig>,
        gateway_config: Option<&GatewayConfig>,
        scope: InventoryScope,
    ) -> Self {
        let mut sources = Vec::new();
        if let Some(env_config) = env_config {
            collect_env_sources(env_config, &mut sources);
        }
        if let Some(gateway_config) = gateway_config {
            collect_gateway_sources(gateway_config, &mut sources);
        }

        let mut grouped = BTreeMap::<String, InventoryEntryBuilder>::new();
        for source_ref in sources {
            let key = inventory_group_key(&source_ref.source, source_ref.kind);
            let id = inventory_entry_id(&source_ref.source, source_ref.kind);
            grouped
                .entry(key)
                .and_modify(|entry| {
                    entry.usages.insert(source_ref.usage.clone());
                })
                .or_insert_with(|| {
                    let mut usages = BTreeSet::new();
                    usages.insert(source_ref.usage);
                    InventoryEntryBuilder {
                        id,
                        source: source_ref.source,
                        kind: source_ref.kind,
                        usages,
                    }
                });
        }

        let entries = grouped
            .into_values()
            .map(|builder| builder.into_entry(scope))
            .collect();
        Self { entries }
    }
}

impl InventoryEntryBuilder {
    fn into_entry(self, scope: InventoryScope) -> TlsInventoryEntry {
        let source_kind = configured_source_kind(&self.source);
        let refreshable = source_is_refreshable(&self.source);
        let material_kind = material_kind_label(self.kind).to_string();
        let mut entry = TlsInventoryEntry {
            id: self.id,
            material_kind,
            source: TlsInventorySource {
                kind: source_kind.as_str().to_string(),
                identifier: self.source.source_id(),
                refreshable,
                version: None,
            },
            state: TlsInventoryState::Loaded,
            used_by: self.usages.into_iter().collect(),
            subject: None,
            issuer: None,
            sans: Vec::new(),
            not_before: None,
            not_after: None,
            days_until_expiry: None,
            fingerprint_sha256: None,
            certificate_count: None,
            crl_count: None,
            error: None,
        };

        if is_pkcs11_key_source(&self.source, self.kind) {
            populate_pkcs11_key_entry(&mut entry);
            return entry;
        }

        if !scope.may_load(self.kind) {
            populate_entry_from_reload_state(&mut entry);
            return entry;
        }

        let material = match load_material_blocking(&self.source, self.kind) {
            Ok(material) => material,
            Err(MaterialError::UnsupportedScheme { .. }) => {
                entry.state = TlsInventoryState::Unsupported;
                entry.error = Some(
                    "source scheme is parsed but runtime loading is not implemented yet"
                        .to_string(),
                );
                return entry;
            }
            Err(MaterialError::Io { source, .. }) => {
                entry.state = TlsInventoryState::Unavailable;
                entry.error = Some(source.to_string());
                return entry;
            }
            Err(error) => {
                entry.state = TlsInventoryState::Invalid;
                entry.error = Some(error.to_string());
                return entry;
            }
        };

        // The *resolved* scheme replaces the configured one (a bare path
        // resolves to `file`), but the identifier stays the configured
        // `source.source_id()` set above. It must not be overwritten with
        // `material.display_source_id`: that value is redacted at the producer,
        // so every `vault://` entry would report the same identifier and the
        // inventory would stop distinguishing sources an operator configured
        // separately. Nothing here needs a redacted rendering — the identifier
        // is the operator's own configured string, on an authenticated admin
        // surface, and it is what `used_by` correlation is read against.
        entry.source.kind = material.source_kind.as_str().to_string();
        entry.source.version = material.version;

        match self.kind {
            MaterialKind::Cert | MaterialKind::CaBundle => {
                if let Err(error) = populate_certificate_metadata(&mut entry, &material.bytes) {
                    entry.state = TlsInventoryState::Invalid;
                    entry.error = Some(error);
                }
            }
            MaterialKind::Key => {
                if let Err(error) = validate_private_key(&material.bytes) {
                    entry.state = TlsInventoryState::Invalid;
                    entry.error = Some(error);
                }
            }
            MaterialKind::Crl => match count_crls(&material.bytes) {
                Ok(count) => {
                    entry.crl_count = Some(count);
                }
                Err(error) => {
                    entry.state = TlsInventoryState::Invalid;
                    entry.error = Some(error);
                }
            },
            MaterialKind::Jwks | MaterialKind::Ocsp | MaterialKind::Unknown => {}
        }

        entry
    }
}

/// Report a source that this scope refuses to materialize.
///
/// The entry keeps its configured provenance and carries no parsed metadata.
/// Health comes from the owning validated config/reload state: startup and
/// every reload validate the source before it is adopted (a broken private key
/// is fatal in file mode, warned in database mode, and rejected in DP mode), so
/// "no recorded failure" means the last validated owner accepted it. A recorded
/// watcher/rebuild failure for the same configured source identity downgrades
/// the entry without re-reading a single byte.
fn populate_entry_from_reload_state(entry: &mut TlsInventoryEntry) {
    let Some(failure) = crate::tls::events::latest_source_failure(&entry.source.identifier) else {
        return;
    };
    tracing::debug!(
        inventory_id = %entry.id,
        outcome = %failure.outcome,
        at = %failure.at,
        "TLS inventory entry reported from the last recorded source failure"
    );
    entry.state = match failure.outcome.as_str() {
        "load_error" => TlsInventoryState::Unavailable,
        _ => TlsInventoryState::Invalid,
    };
    entry.error = failure.error;
}

fn is_pkcs11_key_source(source: &CertSource, kind: MaterialKind) -> bool {
    matches!(
        (source, kind),
        (CertSource::Uri(uri), MaterialKind::Key) if uri.scheme == SourceScheme::Pkcs11
    )
}

fn populate_pkcs11_key_entry(entry: &mut TlsInventoryEntry) {
    if !entry.used_by.iter().all(pkcs11_key_usage_is_supported) {
        entry.state = TlsInventoryState::Unsupported;
        entry.error = Some(
            "PKCS#11 key sources are supported only for frontend/admin server TLS private keys and backend TLS client keys"
                .to_string(),
        );
    } else {
        #[cfg(not(feature = "pkcs11"))]
        {
            populate_pkcs11_feature_missing_entry(entry);
        }
    }
}

fn pkcs11_key_usage_is_supported(usage: &TlsInventoryUsage) -> bool {
    matches!(
        (usage.surface.as_str(), usage.role.as_str()),
        ("frontend_tls" | "admin_tls", "private_key")
            | (
                "backend_tls" | "mesh_route_dispatch",
                "client_key" | "global_client_key"
            )
    )
}

#[cfg(not(feature = "pkcs11"))]
fn populate_pkcs11_feature_missing_entry(entry: &mut TlsInventoryEntry) {
    entry.state = TlsInventoryState::Unsupported;
    entry.error = Some(
        "PKCS#11 key sources require building ferrum-edge with the 'pkcs11' Cargo feature"
            .to_string(),
    );
}

fn collect_env_sources(env: &EnvConfig, sources: &mut Vec<InventorySourceRef>) {
    push_optional_env(
        sources,
        "frontend_tls",
        "server_certificate",
        "FERRUM_FRONTEND_TLS_CERT",
        env.frontend_tls_cert_path.as_deref(),
        MaterialKind::Cert,
    );
    push_optional_env(
        sources,
        "frontend_tls",
        "private_key",
        "FERRUM_FRONTEND_TLS_KEY",
        env.frontend_tls_key_path.as_deref(),
        MaterialKind::Key,
    );
    push_optional_env(
        sources,
        "frontend_tls",
        "client_ca_bundle",
        "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE",
        env.frontend_tls_client_ca_bundle_path.as_deref(),
        MaterialKind::CaBundle,
    );
    push_optional_env(
        sources,
        "frontend_tls",
        "ocsp_response",
        "FERRUM_FRONTEND_TLS_OCSP_RESPONSE",
        env.frontend_tls_ocsp_response_source.as_deref(),
        MaterialKind::Ocsp,
    );
    push_optional_env(
        sources,
        "admin_tls",
        "server_certificate",
        "FERRUM_ADMIN_TLS_CERT",
        env.admin_tls_cert_path.as_deref(),
        MaterialKind::Cert,
    );
    push_optional_env(
        sources,
        "admin_tls",
        "private_key",
        "FERRUM_ADMIN_TLS_KEY",
        env.admin_tls_key_path.as_deref(),
        MaterialKind::Key,
    );
    push_optional_env(
        sources,
        "admin_tls",
        "client_ca_bundle",
        "FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE",
        env.admin_tls_client_ca_bundle_path.as_deref(),
        MaterialKind::CaBundle,
    );
    push_optional_env(
        sources,
        "admin_tls",
        "ocsp_response",
        "FERRUM_ADMIN_TLS_OCSP_RESPONSE",
        env.admin_tls_ocsp_response_source.as_deref(),
        MaterialKind::Ocsp,
    );
    push_optional_env(
        sources,
        "backend_tls",
        "global_ca_bundle",
        "FERRUM_TLS_CA_BUNDLE",
        env.tls_ca_bundle_path.as_deref(),
        MaterialKind::CaBundle,
    );
    push_optional_env(
        sources,
        "backend_tls",
        "global_client_certificate",
        "FERRUM_BACKEND_TLS_CLIENT_CERT",
        env.backend_tls_client_cert_path.as_deref(),
        MaterialKind::Cert,
    );
    push_optional_env(
        sources,
        "backend_tls",
        "global_client_key",
        "FERRUM_BACKEND_TLS_CLIENT_KEY",
        env.backend_tls_client_key_path.as_deref(),
        MaterialKind::Key,
    );
    push_optional_env(
        sources,
        "gateway_svid",
        "certificate",
        "FERRUM_GATEWAY_SVID_CERT",
        env.gateway_svid_cert_path.as_deref(),
        MaterialKind::Cert,
    );
    push_optional_env(
        sources,
        "gateway_svid",
        "private_key",
        "FERRUM_GATEWAY_SVID_KEY",
        env.gateway_svid_key_path.as_deref(),
        MaterialKind::Key,
    );
    push_optional_env(
        sources,
        "gateway_svid",
        "trust_bundle",
        "FERRUM_GATEWAY_SVID_TRUST_BUNDLE",
        env.gateway_svid_trust_bundle_path.as_deref(),
        MaterialKind::CaBundle,
    );
    push_optional_env(
        sources,
        "database_tls",
        "ca_bundle",
        "FERRUM_DB_TLS_CA_CERT",
        env.db_tls_ca_cert_path.as_deref(),
        MaterialKind::CaBundle,
    );
    push_optional_env(
        sources,
        "database_tls",
        "client_certificate",
        "FERRUM_DB_TLS_CLIENT_CERT",
        env.db_tls_client_cert_path.as_deref(),
        MaterialKind::Cert,
    );
    push_optional_env(
        sources,
        "database_tls",
        "client_key",
        "FERRUM_DB_TLS_CLIENT_KEY",
        env.db_tls_client_key_path.as_deref(),
        MaterialKind::Key,
    );
    push_optional_env(
        sources,
        "cp_grpc_tls",
        "server_certificate",
        "FERRUM_CP_GRPC_TLS_CERT",
        env.cp_grpc_tls_cert_path.as_deref(),
        MaterialKind::Cert,
    );
    push_optional_env(
        sources,
        "cp_grpc_tls",
        "private_key",
        "FERRUM_CP_GRPC_TLS_KEY",
        env.cp_grpc_tls_key_path.as_deref(),
        MaterialKind::Key,
    );
    push_optional_env(
        sources,
        "cp_grpc_tls",
        "client_ca_bundle",
        "FERRUM_CP_GRPC_TLS_CLIENT_CA",
        env.cp_grpc_tls_client_ca_path.as_deref(),
        MaterialKind::CaBundle,
    );
    push_optional_env(
        sources,
        "dp_grpc_tls",
        "server_ca_bundle",
        "FERRUM_DP_GRPC_TLS_CA_CERT",
        env.dp_grpc_tls_ca_cert_path.as_deref(),
        MaterialKind::CaBundle,
    );
    push_optional_env(
        sources,
        "dp_grpc_tls",
        "client_certificate",
        "FERRUM_DP_GRPC_TLS_CLIENT_CERT",
        env.dp_grpc_tls_client_cert_path.as_deref(),
        MaterialKind::Cert,
    );
    push_optional_env(
        sources,
        "dp_grpc_tls",
        "client_key",
        "FERRUM_DP_GRPC_TLS_CLIENT_KEY",
        env.dp_grpc_tls_client_key_path.as_deref(),
        MaterialKind::Key,
    );
    push_optional_env(
        sources,
        "dtls",
        "server_certificate",
        "FERRUM_DTLS_CERT",
        env.dtls_cert_path.as_deref(),
        MaterialKind::Cert,
    );
    push_optional_env(
        sources,
        "dtls",
        "private_key",
        "FERRUM_DTLS_KEY",
        env.dtls_key_path.as_deref(),
        MaterialKind::Key,
    );
    push_optional_env(
        sources,
        "dtls",
        "client_ca_bundle",
        "FERRUM_DTLS_CLIENT_CA_CERT",
        env.dtls_client_ca_cert_path.as_deref(),
        MaterialKind::CaBundle,
    );
    push_optional_env(
        sources,
        "revocation",
        "crl_bundle",
        "FERRUM_TLS_CRL_FILE",
        env.tls_crl_file_path.as_deref(),
        MaterialKind::Crl,
    );
}

fn collect_gateway_sources(config: &GatewayConfig, sources: &mut Vec<InventorySourceRef>) {
    for proxy in &config.proxies {
        push_optional_resource(
            sources,
            ResourceUsageRef {
                surface: "backend_tls",
                role: "client_certificate",
                resource_type: "proxy",
                resource_id: &proxy.id,
                field: "backend_tls_client_cert_path",
            },
            proxy.backend_tls_client_cert_path.as_deref(),
            MaterialKind::Cert,
        );
        push_optional_resource(
            sources,
            ResourceUsageRef {
                surface: "backend_tls",
                role: "client_key",
                resource_type: "proxy",
                resource_id: &proxy.id,
                field: "backend_tls_client_key_path",
            },
            proxy.backend_tls_client_key_path.as_deref(),
            MaterialKind::Key,
        );
        push_optional_resource(
            sources,
            ResourceUsageRef {
                surface: "backend_tls",
                role: "server_ca_bundle",
                resource_type: "proxy",
                resource_id: &proxy.id,
                field: "backend_tls_server_ca_cert_path",
            },
            proxy.backend_tls_server_ca_cert_path.as_deref(),
            MaterialKind::CaBundle,
        );
    }

    for upstream in &config.upstreams {
        push_optional_resource(
            sources,
            ResourceUsageRef {
                surface: "backend_tls",
                role: "client_certificate",
                resource_type: "upstream",
                resource_id: &upstream.id,
                field: "backend_tls_client_cert_path",
            },
            upstream.backend_tls_client_cert_path.as_deref(),
            MaterialKind::Cert,
        );
        push_optional_resource(
            sources,
            ResourceUsageRef {
                surface: "backend_tls",
                role: "client_key",
                resource_type: "upstream",
                resource_id: &upstream.id,
                field: "backend_tls_client_key_path",
            },
            upstream.backend_tls_client_key_path.as_deref(),
            MaterialKind::Key,
        );
        push_optional_resource(
            sources,
            ResourceUsageRef {
                surface: "backend_tls",
                role: "server_ca_bundle",
                resource_type: "upstream",
                resource_id: &upstream.id,
                field: "backend_tls_server_ca_cert_path",
            },
            upstream.backend_tls_server_ca_cert_path.as_deref(),
            MaterialKind::CaBundle,
        );
    }

    for plugin in &config.plugin_configs {
        collect_mesh_route_dispatch_sources(plugin, sources);
    }
}

fn collect_mesh_route_dispatch_sources(
    plugin: &PluginConfig,
    sources: &mut Vec<InventorySourceRef>,
) {
    if !plugin.enabled || plugin.plugin_name != "mesh_route_dispatch" {
        return;
    }
    let Some(rules) = plugin.config.get("rules").and_then(Value::as_array) else {
        return;
    };

    for (idx, rule) in rules.iter().enumerate() {
        let Some(backend_tls) = rule
            .get("destination")
            .and_then(|destination| destination.get("backend_tls"))
            .and_then(Value::as_object)
        else {
            continue;
        };
        let resource_id = format!("{}#rule[{idx}]", plugin.id);
        push_optional_resource(
            sources,
            ResourceUsageRef {
                surface: "mesh_route_dispatch",
                role: "client_certificate",
                resource_type: "plugin_config",
                resource_id: &resource_id,
                field: "destination.backend_tls.client_cert_path",
            },
            backend_tls.get("client_cert_path").and_then(Value::as_str),
            MaterialKind::Cert,
        );
        push_optional_resource(
            sources,
            ResourceUsageRef {
                surface: "mesh_route_dispatch",
                role: "client_key",
                resource_type: "plugin_config",
                resource_id: &resource_id,
                field: "destination.backend_tls.client_key_path",
            },
            backend_tls.get("client_key_path").and_then(Value::as_str),
            MaterialKind::Key,
        );
        push_optional_resource(
            sources,
            ResourceUsageRef {
                surface: "mesh_route_dispatch",
                role: "server_ca_bundle",
                resource_type: "plugin_config",
                resource_id: &resource_id,
                field: "destination.backend_tls.server_ca_cert_path",
            },
            backend_tls
                .get("server_ca_cert_path")
                .and_then(Value::as_str),
            MaterialKind::CaBundle,
        );
    }
}

fn push_optional_env(
    sources: &mut Vec<InventorySourceRef>,
    surface: &'static str,
    role: &'static str,
    field: &'static str,
    value: Option<&str>,
    kind: MaterialKind,
) {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return;
    };
    sources.push(InventorySourceRef {
        source: CertSource::parse(value.to_string(), kind),
        kind,
        usage: TlsInventoryUsage {
            surface: surface.to_string(),
            role: role.to_string(),
            resource_type: "env".to_string(),
            resource_id: "runtime".to_string(),
            field: field.to_string(),
        },
    });
}

fn push_optional_resource(
    sources: &mut Vec<InventorySourceRef>,
    usage: ResourceUsageRef<'_>,
    value: Option<&str>,
    kind: MaterialKind,
) {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return;
    };
    sources.push(InventorySourceRef {
        source: CertSource::parse(value.to_string(), kind),
        kind,
        usage: TlsInventoryUsage {
            surface: usage.surface.to_string(),
            role: usage.role.to_string(),
            resource_type: usage.resource_type.to_string(),
            resource_id: usage.resource_id.to_string(),
            field: usage.field.to_string(),
        },
    });
}

fn configured_source_kind(source: &CertSource) -> SourceScheme {
    match source {
        CertSource::Path(_) | CertSource::InlinePem(_) => SourceScheme::File,
        CertSource::Uri(uri) => uri.scheme,
    }
}

fn inventory_group_key(source: &CertSource, kind: MaterialKind) -> String {
    format!(
        "{}|{}",
        material_kind_label(kind),
        source.pool_key_component()
    )
}

fn inventory_entry_id(source: &CertSource, kind: MaterialKind) -> String {
    let digest = Sha256::digest(inventory_group_key(source, kind).as_bytes());
    format!(
        "{}-{}",
        material_kind_label(kind),
        hex::encode(&digest[..8])
    )
}

fn material_kind_label(kind: MaterialKind) -> &'static str {
    match kind {
        MaterialKind::Cert => "certificate",
        MaterialKind::Key => "private_key",
        MaterialKind::CaBundle => "ca_bundle",
        MaterialKind::Crl => "crl",
        MaterialKind::Jwks => "jwks",
        MaterialKind::Ocsp => "ocsp",
        MaterialKind::Unknown => "unknown",
    }
}

fn populate_certificate_metadata(
    entry: &mut TlsInventoryEntry,
    bytes: &crate::tls::source::SecretBytes,
) -> Result<(), String> {
    let certs = rustls_pemfile::certs(&mut Cursor::new(bytes.expose_secret()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to parse PEM certificates: {error}"))?;
    if certs.is_empty() {
        return Err("no PEM certificates found".to_string());
    }

    let leaf = certs
        .first()
        .ok_or_else(|| "no PEM certificates found".to_string())?;
    let (_, parsed_leaf) = X509Certificate::from_der(leaf.as_ref())
        .map_err(|error| format!("failed to parse leaf certificate: {error}"))?;
    let validity = parsed_leaf.validity();
    let not_before_ts = validity.not_before.timestamp();
    let not_after_ts = validity.not_after.timestamp();
    let now_ts = ASN1Time::now().timestamp();

    entry.subject = Some(parsed_leaf.subject().to_string());
    entry.issuer = Some(parsed_leaf.issuer().to_string());
    entry.sans = certificate_sans(&parsed_leaf);
    entry.not_before = DateTime::<Utc>::from_timestamp(not_before_ts, 0);
    entry.not_after = DateTime::<Utc>::from_timestamp(not_after_ts, 0);
    entry.days_until_expiry = Some((not_after_ts - now_ts) / 86_400);
    entry.fingerprint_sha256 = Some(hex::encode(Sha256::digest(leaf.as_ref())));
    entry.certificate_count = Some(certs.len());
    Ok(())
}

fn certificate_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut sans = BTreeSet::new();
    for extension in cert.extensions() {
        let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() else {
            continue;
        };
        for name in &san.general_names {
            match name {
                GeneralName::DNSName(value) => {
                    sans.insert(format!("dns:{value}"));
                }
                GeneralName::IPAddress(value) => {
                    sans.insert(format!("ip:{}", hex::encode(value)));
                }
                GeneralName::URI(value) => {
                    sans.insert(format!("uri:{value}"));
                }
                GeneralName::RFC822Name(value) => {
                    sans.insert(format!("email:{value}"));
                }
                _ => {}
            }
        }
    }
    sans.into_iter().collect()
}

fn validate_private_key(bytes: &crate::tls::source::SecretBytes) -> Result<(), String> {
    rustls_pemfile::private_key(&mut Cursor::new(bytes.expose_secret()))
        .map_err(|error| format!("failed to parse PEM private key: {error}"))?
        .ok_or_else(|| "no PEM private key found".to_string())
        .map(|_| ())
}

fn count_crls(bytes: &crate::tls::source::SecretBytes) -> Result<usize, String> {
    let crls = rustls_pemfile::crls(&mut Cursor::new(bytes.expose_secret()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to parse PEM CRLs: {error}"))?;
    if crls.is_empty() {
        return Err("no PEM CRLs found".to_string());
    }
    Ok(crls.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated_cert_and_key() -> (String, String) {
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let cert = params.self_signed(&key_pair).expect("self-sign cert");
        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn inventory_groups_duplicate_sources_and_redacts_inline_material() {
        let (cert_pem, _) = generated_cert_and_key();
        let mut config = GatewayConfig::default();
        config.proxies.push(
            serde_json::from_value(serde_json::json!({
                "id": "api",
                "hosts": ["api.example.test"],
                "backend_host": "127.0.0.1",
                "backend_port": 443,
                "backend_tls_client_cert_path": cert_pem.clone()
            }))
            .expect("proxy"),
        );
        config.upstreams.push(
            serde_json::from_value(serde_json::json!({
                "id": "svc",
                "targets": [],
                "backend_tls_client_cert_path": cert_pem
            }))
            .expect("upstream"),
        );

        let inventory = TlsInventory::collect(None, Some(&config));
        assert_eq!(inventory.entries.len(), 1);
        let entry = &inventory.entries[0];
        assert_eq!(entry.material_kind, "certificate");
        assert_eq!(entry.state, TlsInventoryState::Loaded);
        assert_eq!(entry.used_by.len(), 2);
        assert_eq!(entry.source.identifier, "inline-pem:<redacted>");
        assert!(
            !serde_json::to_string(entry)
                .expect("json")
                .contains("BEGIN CERTIFICATE")
        );
        assert_eq!(entry.certificate_count, Some(1));
        assert!(entry.fingerprint_sha256.is_some());
    }

    #[test]
    fn inventory_validates_private_keys_without_exposing_fingerprint() {
        let (_, key_pem) = generated_cert_and_key();
        let mut config = GatewayConfig::default();
        config.proxies.push(
            serde_json::from_value(serde_json::json!({
                "id": "api",
                "hosts": ["api.example.test"],
                "backend_host": "127.0.0.1",
                "backend_port": 443,
                "backend_tls_client_key_path": key_pem
            }))
            .expect("proxy"),
        );

        let inventory = TlsInventory::collect(None, Some(&config));
        assert_eq!(inventory.entries.len(), 1);
        let entry = &inventory.entries[0];
        assert_eq!(entry.material_kind, "private_key");
        assert_eq!(entry.state, TlsInventoryState::Loaded);
        assert!(entry.fingerprint_sha256.is_none());
    }

    #[test]
    fn inventory_reports_backend_pkcs11_key_sources_without_loading_key_bytes() {
        let mut config = GatewayConfig::default();
        config.proxies.push(
            serde_json::from_value(serde_json::json!({
                "id": "api",
                "hosts": ["api.example.test"],
                "backend_host": "127.0.0.1",
                "backend_port": 443,
                "backend_tls_client_key_path": "pkcs11://edge-rsa?module=/usr/lib/pkcs11.so&pin_env=FERRUM_PKCS11_PIN"
            }))
            .expect("proxy"),
        );

        let inventory = TlsInventory::collect(None, Some(&config));
        assert_eq!(inventory.entries.len(), 1);
        let entry = &inventory.entries[0];
        assert_eq!(entry.material_kind, "private_key");
        assert_eq!(entry.source.kind, "pkcs11");
        assert!(entry.fingerprint_sha256.is_none());
        assert!(
            serde_json::to_string(entry)
                .expect("json")
                .contains("pkcs11://edge-rsa")
        );
        #[cfg(feature = "pkcs11")]
        assert_eq!(entry.state, TlsInventoryState::Loaded);
        #[cfg(not(feature = "pkcs11"))]
        {
            assert_eq!(entry.state, TlsInventoryState::Unsupported);
            assert!(
                entry
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains("'pkcs11' Cargo feature"))
            );
        }
    }

    #[test]
    fn inventory_reports_frontend_pkcs11_key_sources_without_loading_key_bytes() {
        let env = EnvConfig {
            frontend_tls_key_path: Some(
                "pkcs11://edge-rsa?module=/usr/lib/pkcs11.so&pin_env=FERRUM_PKCS11_PIN".to_string(),
            ),
            ..EnvConfig::default()
        };

        let inventory = TlsInventory::collect(Some(&env), None);
        assert_eq!(inventory.entries.len(), 1);
        let entry = &inventory.entries[0];
        assert_eq!(entry.material_kind, "private_key");
        assert_eq!(entry.source.kind, "pkcs11");
        assert!(entry.fingerprint_sha256.is_none());
        #[cfg(feature = "pkcs11")]
        assert_eq!(entry.state, TlsInventoryState::Loaded);
        #[cfg(not(feature = "pkcs11"))]
        {
            assert_eq!(entry.state, TlsInventoryState::Unsupported);
            assert!(
                entry
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains("'pkcs11' Cargo feature"))
            );
        }
    }
}
