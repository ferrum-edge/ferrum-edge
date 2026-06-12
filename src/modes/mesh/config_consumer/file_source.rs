//! Localized file-based mesh config source (`FERRUM_MESH_CONFIG_PROTOCOL=file`).
//!
//! Instead of subscribing to a control plane, the data plane builds its
//! [`MeshSlice`] locally from a YAML/JSON document on disk — the same
//! DP-side materialization path the native/xDS consumers feed
//! (`MeshSlice::from_gateway_config` + the slice-apply task), so a file-built
//! slice is functionally equivalent to a CP-delivered one. Mirrors the
//! gateway's file mode: the initial load is fail-closed (an unreadable or
//! invalid document refuses startup) and SIGHUP (Unix) reloads the document,
//! keeping the last good slice when the reload fails.
//!
//! The document carries only the `mesh` section (plus an optional `version`
//! stamp); gateway resources (proxies/upstreams/consumers/plugins) are
//! rejected — mesh mode materializes its routes from the slice, and operators
//! who need plain gateway routes should run file mode.

use std::path::Path;

use serde::Deserialize;
use tracing::{info, warn};

use crate::config::types::{CURRENT_CONFIG_VERSION, GatewayConfig};
use crate::modes::mesh::runtime::MeshRuntimeState;
use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};

/// On-disk shape of the localized mesh config document.
///
/// `deny_unknown_fields` is load-bearing: a document carrying gateway
/// resources (`proxies:`, `upstreams:`, ...) fails deserialization with a
/// clear "unknown field" error instead of silently dropping them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MeshFileDocument {
    /// Optional config schema version stamp. When present it must match
    /// [`CURRENT_CONFIG_VERSION`]; the mesh model has no file migrations.
    #[serde(default)]
    version: Option<String>,
    mesh: Box<crate::modes::mesh::config::MeshConfig>,
}

/// Load the mesh document at `path` and build the node's [`MeshSlice`].
///
/// Runs the same normalization + validation the CP-side slice builder applies
/// (`normalize_fields`/`normalize_mesh_fields` + `validate_mesh_fields`)
/// before narrowing via [`MeshSlice::from_gateway_config`], so a document the
/// initial load accepts cannot later be rejected by the slice-apply task for
/// mesh-field validity.
pub fn load_mesh_slice_from_file(
    path: &Path,
    request: MeshSliceRequest,
) -> Result<MeshSlice, anyhow::Error> {
    if !path.exists() {
        anyhow::bail!("mesh configuration file not found: {}", path.display());
    }

    // Mirror file mode's credential-hygiene warning: mesh documents can carry
    // JWT issuer material and trust bundles.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mode = metadata.permissions().mode();
            if mode & 0o004 != 0 {
                warn!(
                    "Mesh config file {} is world-readable (mode {:o}). Consider restricting \
                     permissions as it may contain trust material.",
                    path.display(),
                    mode & 0o777
                );
            }
        }
    }

    let content = std::fs::read_to_string(path)?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    // Same format detection as the gateway file loader: extension first, then
    // a YAML-parse heuristic (YAML is a JSON superset, so the fallback only
    // matters for diagnostics).
    let is_yaml = match ext.as_str() {
        "yaml" | "yml" => true,
        "json" => false,
        _ => serde_yaml::from_str::<serde_yaml::Value>(&content).is_ok(),
    };

    let document: MeshFileDocument = if is_yaml {
        serde_yaml::from_str(&content).map_err(|e| anyhow::anyhow!(mesh_doc_parse_error(e)))?
    } else {
        serde_json::from_str(&content).map_err(|e| anyhow::anyhow!(mesh_doc_parse_error(e)))?
    };

    if let Some(version) = document.version.as_deref()
        && version != CURRENT_CONFIG_VERSION
    {
        anyhow::bail!(
            "mesh configuration file declares version '{version}' but this gateway expects \
             '{CURRENT_CONFIG_VERSION}' (the mesh model has no file migrations)"
        );
    }

    let mut config = GatewayConfig {
        version: CURRENT_CONFIG_VERSION.to_string(),
        mesh: Some(document.mesh),
        loaded_at: chrono::Utc::now(),
        ..GatewayConfig::default()
    };
    config.normalize_fields();
    config.normalize_mesh_fields();
    let mesh_errors = config.validate_mesh_fields();
    if !mesh_errors.is_empty() {
        anyhow::bail!(
            "mesh configuration validation failed: {}",
            mesh_errors.join("; ")
        );
    }

    Ok(MeshSlice::from_gateway_config(&config, request))
}

/// Wrap a serde error with a pointer at the document contract so an operator
/// who fed a full gateway config file gets steered instead of puzzled by a
/// bare "unknown field `proxies`".
fn mesh_doc_parse_error(err: impl std::fmt::Display) -> String {
    format!(
        "invalid mesh configuration document: {err} (the localized mesh source consumes only an \
         optional `version` plus the `mesh` section; gateway resources such as proxies/upstreams \
         belong to FERRUM_MODE=file)"
    )
}

/// Reload the mesh document on SIGHUP (Unix), keeping the last good slice
/// when a reload fails. The initial load happens before this task is spawned
/// (fail-closed at startup); identical reloads are deduped downstream by the
/// slice-apply task's `content_eq` check.
pub async fn start_mesh_file_source_with_shutdown(
    path: String,
    request: MeshSliceRequest,
    state: MeshRuntimeState,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    #[cfg(unix)]
    {
        let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to register SIGHUP handler for mesh file source; the mesh \
                     document will not reload until restart"
                );
                super::common::wait_for_shutdown(&mut shutdown_rx).await;
                return;
            }
        };
        loop {
            tokio::select! {
                received = hangup.recv() => {
                    if received.is_none() {
                        warn!(
                            "SIGHUP stream closed; mesh file source will not reload until restart"
                        );
                        super::common::wait_for_shutdown(&mut shutdown_rx).await;
                        return;
                    }
                    match load_mesh_slice_from_file(Path::new(&path), request.clone()) {
                        Ok(slice) => {
                            info!(
                                file_path = %path,
                                mesh_slice_version = %slice.version,
                                "Reloaded mesh config file on SIGHUP"
                            );
                            state.install_slice(slice);
                        }
                        Err(e) => {
                            warn!(
                                file_path = %path,
                                error = %e,
                                "Failed to reload mesh config file on SIGHUP; keeping the last \
                                 good mesh slice"
                            );
                        }
                    }
                }
                _ = super::common::wait_for_shutdown(&mut shutdown_rx) => {
                    info!("Mesh file source shutting down");
                    return;
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        info!(
            file_path = %path,
            "Mesh file source loaded; live reload is Unix-only (SIGHUP), restart to pick up \
             changes"
        );
        let _ = &request;
        let _ = &state;
        super::common::wait_for_shutdown(&mut shutdown_rx).await;
    }
}
