// Compile a local copy of the mesh subset of proto/ferrum.proto.
// We only need the MeshConfigSync service (the harness does not implement
// or call ConfigSync). Build the file in-place so the harness Cargo.lock stays
// independent of the root crate.

use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let proto_dir = out_dir.join("proto");
    fs::create_dir_all(&proto_dir).expect("create proto dir");

    let proto_path = proto_dir.join("mesh.proto");
    fs::write(&proto_path, MESH_PROTO).expect("write mesh.proto");

    println!("cargo:rerun-if-changed=build.rs");

    if let Err(e) = tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto_path], &[proto_dir])
    {
        eprintln!("Warning: failed to compile mesh.proto: {e}");
        std::process::exit(1);
    }
}

// Mirror of the MeshConfigSync subset of proto/ferrum.proto. Keep the
// wire shape (field tags, field names) identical — the gateway binary parses
// this. Drop the ConfigSync service entirely (not used here).
//
// SYNC: when proto/ferrum.proto MeshConfigSync changes, mirror the change
// here. Field tag drift will silently break the stub.
const MESH_PROTO: &str = r#"syntax = "proto3";

package ferrum;

service MeshConfigSync {
  rpc MeshSubscribe(MeshSubscribeRequest) returns (stream MeshConfigUpdate);
  rpc ReportMeshSliceStatus(MeshSliceStatusReport) returns (MeshSliceStatusResponse);
}

message MeshSubscribeRequest {
  string node_id = 1;
  string ferrum_version = 2;
  string namespace = 3;
  string workload_spiffe_id = 4;
  map<string, string> labels = 5;
  string waypoint_name = 6;
}

message MeshConfigUpdate {
  string version = 1;
  int64 timestamp = 2;
  string mesh_slice_json = 3;
  string ferrum_version = 4;
  bool heartbeat = 5;
  string config_authority = 6;
  uint64 config_sequence = 7;
  string session_token = 8;
}

enum MeshSliceStatusPhase {
  MESH_SLICE_STATUS_PHASE_ACCEPTED = 0;
  MESH_SLICE_STATUS_PHASE_APPLIED = 1;
}

enum MeshSliceRejectReason {
  MESH_SLICE_REJECT_REASON_UNSPECIFIED = 0;
  MESH_SLICE_REJECT_REASON_INSTALL_REFUSED = 1;
  MESH_SLICE_REJECT_REASON_RUNTIME_CONFIG_BUILD = 2;
  MESH_SLICE_REJECT_REASON_RUNTIME_PROXY_REFUSED = 3;
  MESH_SLICE_REJECT_REASON_RUNTIME_TRUST_UNUSABLE = 4;
  MESH_SLICE_REJECT_REASON_RUNTIME_TLS_RELOAD = 5;
  MESH_SLICE_REJECT_REASON_RUNTIME_DTLS_CANDIDATE = 6;
}

message MeshSliceStatusReport {
  string version = 1;
  string session_token = 3;
  MeshSliceStatusPhase phase = 4;
  MeshSliceRejectReason reject_reason = 5;
}

message MeshSliceStatusResponse {}
"#;
