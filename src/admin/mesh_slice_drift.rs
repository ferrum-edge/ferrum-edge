//! Response builder for `GET /mesh/slice-drift` (issue #3265).
//!
//! CP-mode admin surface that exposes per-authenticated-DP desired / sent /
//! acknowledged (accepted) / applied / rejected mesh slice versions so
//! operators can diff the control plane's publish view against what each data
//! plane accepted at install time AND what its proxy runtime is actually
//! serving (issue #4812).

use serde::Serialize;

use crate::grpc::mesh_slice_drift::MeshSliceDriftSnapshot;

/// Top-level JSON envelope for `GET /mesh/slice-drift`.
#[derive(Debug, Clone, Serialize)]
pub struct MeshSliceDriftResponse {
    pub mode: &'static str,
    pub generated_at: String,
    pub summary: crate::grpc::mesh_slice_drift::MeshSliceDriftSummary,
    pub data_planes: Vec<crate::grpc::mesh_slice_drift::MeshSliceDriftEntry>,
}

/// Build the admin response from an immutable drift snapshot.
pub fn build_response(snapshot: &MeshSliceDriftSnapshot) -> MeshSliceDriftResponse {
    MeshSliceDriftResponse {
        mode: "cp",
        generated_at: snapshot.generated_at.to_rfc3339(),
        summary: snapshot.summary.clone(),
        data_planes: snapshot.data_planes.clone(),
    }
}
