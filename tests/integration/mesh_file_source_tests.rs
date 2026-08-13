//! Localized file mesh config source (`FERRUM_MESH_CONFIG_PROTOCOL=file`).
//!
//! Exercises `config_consumer::file_source::load_mesh_slice_from_file`: the
//! document contract (mesh section only, optional `version` stamp), fail-closed
//! validation, and slice-building parity with the CP-side materialization
//! (namespace scoping, version stamping from `loaded_at`).

use std::io::Write;

use ferrum_edge::modes::mesh::config_consumer::file_source::load_mesh_slice_from_file;
use ferrum_edge::modes::mesh::slice::MeshSliceRequest;

fn request_for_namespace(namespace: &str) -> MeshSliceRequest {
    MeshSliceRequest {
        node_id: "file-source-node".to_string(),
        namespace: namespace.to_string(),
        ..MeshSliceRequest::default()
    }
}

fn write_temp(ext: &str, content: &str) -> tempfile::TempPath {
    let mut file = tempfile::Builder::new()
        .suffix(&format!(".{ext}"))
        .tempfile()
        .expect("create temp mesh config");
    file.write_all(content.as_bytes())
        .expect("write temp mesh config");
    file.into_temp_path()
}

const VALID_MESH_YAML: &str = r#"
version: "1"
mesh:
  workloads:
    - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
      selector:
        labels:
          app: api
      service_name: api
      addresses: ["10.0.0.5"]
      ports:
        - port: 8080
          protocol: http
      trust_domain: cluster.local
      namespace: ferrum
  services:
    - name: api
      namespace: ferrum
      ports:
        - port: 80
          protocol: http
      workloads:
        - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
"#;

#[test]
fn loads_yaml_mesh_document_and_builds_slice() {
    let path = write_temp("yaml", VALID_MESH_YAML);
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect("valid mesh document loads");

    assert_eq!(slice.node_id, "file-source-node");
    assert_eq!(slice.namespace, "ferrum");
    assert_eq!(slice.workloads.len(), 1);
    assert_eq!(slice.services.len(), 1);
    assert_eq!(slice.services[0].name, "api");
    assert!(
        !slice.version.is_empty(),
        "slice version must carry the load timestamp"
    );
    chrono::DateTime::parse_from_rfc3339(&slice.version)
        .expect("file-built slice version is the RFC3339 load timestamp");
}

#[test]
fn loads_json_mesh_document() {
    let json = serde_json::json!({
        "mesh": {
            "services": [{
                "name": "api",
                "namespace": "ferrum",
                "ports": [{"port": 80, "protocol": "http"}],
            }],
        }
    });
    let path = write_temp("json", &json.to_string());
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect("valid JSON mesh document loads");
    assert_eq!(slice.services.len(), 1);
}

#[test]
fn slice_building_scopes_by_request_namespace() {
    // Namespace scoping happens DP-side for the file source — the same
    // `MeshSlice::from_gateway_config` narrowing the CP applies.
    let path = write_temp("yaml", VALID_MESH_YAML);
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("other"))
        .expect("document loads under a different namespace");
    assert!(
        slice.services.is_empty() && slice.workloads.is_empty(),
        "resources in 'ferrum' must not leak into the 'other' namespace slice"
    );
}

#[test]
fn rejects_gateway_resources_in_mesh_document() {
    let doc = r#"
version: "1"
proxies: []
mesh:
  services: []
"#;
    let path = write_temp("yaml", doc);
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("gateway resources must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("proxies") && msg.contains("FERRUM_MODE=file"),
        "error must name the offending field and steer to file mode: {msg}"
    );
}

#[test]
fn rejects_document_without_mesh_section() {
    let path = write_temp("yaml", "version: \"1\"\n");
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("a document without a mesh section must be rejected");
    assert!(err.to_string().contains("mesh"), "{err}");
}

#[test]
fn rejects_unknown_version_stamp() {
    let doc = r#"
version: "999"
mesh:
  services: []
"#;
    let path = write_temp("yaml", doc);
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("an unknown version stamp must be rejected");
    assert!(err.to_string().contains("version"), "{err}");
}

#[test]
fn rejects_invalid_mesh_fields() {
    // Port 0 fails `validate_mesh_fields` — the same validation the
    // slice-apply task would run; the file source fails it eagerly so startup
    // is fail-closed.
    let doc = r#"
mesh:
  services:
    - name: api
      namespace: ferrum
      ports:
        - port: 0
          protocol: http
"#;
    let path = write_temp("yaml", doc);
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("invalid mesh fields must be rejected");
    assert!(
        err.to_string().contains("validation failed"),
        "expected a mesh validation error, got: {err}"
    );
}

#[test]
fn missing_file_is_an_error() {
    let err = load_mesh_slice_from_file(
        std::path::Path::new("/nonexistent/ferrum-mesh-config.yaml"),
        request_for_namespace("ferrum"),
    )
    .expect_err("missing file must be an error");
    assert!(err.to_string().contains("not found"), "{err}");
}

#[test]
fn reload_then_load_produces_advancing_versions() {
    // The slice version is the load timestamp: two loads of the same document
    // produce slices that are `content_eq` (so the apply task no-ops) while
    // the version stamp itself advances.
    let path = write_temp("yaml", VALID_MESH_YAML);
    let first = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect("first load succeeds");
    // Two `Utc::now()` stamps in the same instant would compare equal and
    // mask the assertion; force distinct timestamps.
    std::thread::sleep(std::time::Duration::from_millis(2));
    let second = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect("second load succeeds");
    assert!(
        first.content_eq(&second),
        "identical documents must build content-equal slices"
    );
    assert_ne!(
        first.version, second.version,
        "each load stamps its own version"
    );
}

#[test]
fn mesh_file_oversized_sparse_document_is_refused() {
    use ferrum_edge::config::stable_file::MAX_MESH_CONFIG_FILE_BYTES;

    let dir = tempfile::tempdir().unwrap();
    let over = dir.path().join("mesh-over.yaml");
    let file = std::fs::File::create(&over).unwrap();
    file.set_len(MAX_MESH_CONFIG_FILE_BYTES + 1).unwrap();
    drop(file);
    let err =
        load_mesh_slice_from_file(&over, request_for_namespace("ferrum")).expect_err("limit+1");
    let msg = err.to_string();
    assert!(
        msg.contains("maximum supported size is 67108864 bytes"),
        "expected size diagnostic, got: {msg}"
    );
}

#[test]
fn mesh_file_at_documented_ceiling_constant_is_admitted_by_stable_reader() {
    // Full 64 MiB fixtures are covered by `stable_file_tests` at a reduced
    // ceiling; this pins the mesh source to that shared constant/primitive.
    use ferrum_edge::config::stable_file::{
        MAX_MESH_CONFIG_FILE_BYTES, StableFileReadOptions, read_stable_file,
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mesh.yaml");
    std::fs::write(&path, VALID_MESH_YAML).unwrap();
    let options = StableFileReadOptions::new(MAX_MESH_CONFIG_FILE_BYTES, "mesh configuration file");
    read_stable_file(&path, options).expect("valid mesh document under ceiling");
    load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).expect("loads");
}

#[test]
fn unknown_extension_json_object_parses_once_through_yaml_superset() {
    // Unknown paths use the YAML parser directly. JSON remains accepted because
    // it is a YAML subset, and YAML flow mappings retain their historical
    // behavior instead of being misclassified as strict JSON.
    let json = serde_json::json!({
        "mesh": {
            "services": [{
                "name": "api",
                "namespace": "ferrum",
                "ports": [{"port": 80, "protocol": "http"}],
            }],
        }
    });
    let mut file = tempfile::Builder::new()
        .suffix(".unknown")
        .tempfile()
        .unwrap();
    write!(file, "{}", json).unwrap();
    let slice = load_mesh_slice_from_file(file.path(), request_for_namespace("ferrum"))
        .expect("JSON-shaped unknown extension");
    assert_eq!(slice.services.len(), 1);

    let flow_yaml = write_temp(
        "unknown",
        "{mesh: {services: [{name: api, namespace: ferrum, ports: [{port: 80, protocol: http}]}]}}",
    );
    let flow_slice = load_mesh_slice_from_file(&flow_yaml, request_for_namespace("ferrum"))
        .expect("YAML flow mapping with unknown extension");
    assert_eq!(flow_slice.services.len(), 1);
}

#[test]
fn malformed_yaml_fails_without_echoing_document_body() {
    let path = write_temp("yaml", "mesh: [\n  this is not valid\n");
    let err =
        load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).expect_err("malformed");
    let msg = err.to_string();
    assert!(
        msg.contains("invalid mesh configuration document"),
        "got: {msg}"
    );
}

#[cfg(unix)]
#[test]
fn fifo_mesh_path_is_rejected_promptly() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("mesh.yaml");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success());
    let started = std::time::Instant::now();
    let err = load_mesh_slice_from_file(&fifo, request_for_namespace("ferrum")).expect_err("fifo");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    let msg = err.to_string();
    assert!(msg.contains("not a regular file"), "got: {msg}");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_reload_does_not_stall_tokio_heartbeat() {
    use ferrum_edge::config::stable_file::MAX_MESH_CONFIG_FILE_BYTES;
    use ferrum_edge::modes::mesh::config_consumer::file_source::load_mesh_slice_from_file_off_thread;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    // A multi-MiB stable read (two full probes) must run on the blocking pool
    // so a Tokio heartbeat/timer on a core worker keeps advancing.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large-mesh.yaml");
    let mut body = VALID_MESH_YAML.to_string();
    body.push('\n');
    let target = (8 * 1024 * 1024).min(MAX_MESH_CONFIG_FILE_BYTES as usize);
    let pad = target.saturating_sub(body.len());
    body.push('#');
    if pad > 1 {
        body.push_str(&"x".repeat(pad - 1));
    }
    std::fs::write(&path, &body).unwrap();

    let heartbeat = Arc::new(AtomicBool::new(false));
    let heartbeat_flag = Arc::clone(&heartbeat);
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            heartbeat_flag.store(true, Ordering::SeqCst);
        }
    });

    let load = tokio::spawn(load_mesh_slice_from_file_off_thread(
        path.clone(),
        request_for_namespace("ferrum"),
    ));

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !heartbeat.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Tokio heartbeat must advance while a large mesh file load runs off-thread");

    let loaded = load.await.expect("join").expect("large mesh loads");
    assert_eq!(loaded.services.len(), 1);
    ticker.abort();
    let _ = ticker.await;
}

#[test]
fn mesh_reload_generation_advances_on_signal_and_stales_inflight_candidate() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::{
        mesh_reload_generation_is_current, record_mesh_reload_request,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    let latest = AtomicU64::new(0);
    let gen1 = record_mesh_reload_request(&latest);
    assert_eq!(gen1, 1);
    assert!(mesh_reload_generation_is_current(
        gen1,
        latest.load(Ordering::Acquire)
    ));

    // A signal observed during an in-flight load must advance the requested
    // generation immediately so the older candidate cannot install.
    let gen2 = record_mesh_reload_request(&latest);
    assert_eq!(gen2, 2);
    assert!(
        !mesh_reload_generation_is_current(gen1, latest.load(Ordering::Acquire)),
        "in-flight gen1 must be stale once a later signal is observed"
    );
    assert!(mesh_reload_generation_is_current(
        gen2,
        latest.load(Ordering::Acquire)
    ));

    // Coalesced follow-up signals collapse to one newer requested generation.
    let gen3 = record_mesh_reload_request(&latest);
    assert_eq!(gen3, 3);
    assert!(!mesh_reload_generation_is_current(gen2, 3));
    assert!(mesh_reload_generation_is_current(gen3, 3));
    // Exact equality only: a future/out-of-contract generation is not current.
    assert!(!mesh_reload_generation_is_current(4, 3));
}

#[test]
fn mesh_local_source_recovery_requires_proxy_accept_and_fences_generations() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::{
        MeshLocalReloadApply, MeshLocalSourceRecovery, apply_mesh_file_reload_candidate,
    };
    use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
    use ferrum_edge::modes::mesh::slice::MeshSlice;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let path = write_temp("yaml", VALID_MESH_YAML);
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();
    let state = MeshRuntimeState::new();
    state.install_slice(slice.clone());
    let flag = Arc::new(AtomicBool::new(false));
    let recovery = MeshLocalSourceRecovery::new(flag.clone());

    // Failure raises sticky health and retains last-good.
    let rejected = apply_mesh_file_reload_candidate(
        &state,
        &recovery,
        load_mesh_slice_from_file(
            std::path::Path::new("/nonexistent/ferrum-mesh-reload.yaml"),
            request_for_namespace("ferrum"),
        ),
    );
    assert_eq!(rejected, MeshLocalReloadApply::Rejected);
    assert!(recovery.is_rejected());
    assert!(
        state
            .snapshot()
            .as_ref()
            .as_ref()
            .unwrap()
            .content_eq(&slice)
    );

    // Valid candidate installs but must NOT clear until proxy accept.
    let recovered = apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice.clone()));
    assert!(matches!(
        recovered,
        MeshLocalReloadApply::Applied | MeshLocalReloadApply::Unchanged
    ));
    assert!(
        recovery.is_rejected(),
        "provisional install_slice must leave config_rejected set"
    );
    assert_ne!(recovery.pending_epoch(), 0);

    // Exact current accepted recovery clears.
    recovery.note_proxy_apply_success(&slice);
    assert!(!recovery.is_rejected());
    assert_eq!(recovery.pending_epoch(), 0);

    // Unchanged recovery also clears only after proxy no-op accept.
    recovery.mark_rejected();
    let unchanged = apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice.clone()));
    assert_eq!(unchanged, MeshLocalReloadApply::Unchanged);
    assert!(recovery.is_rejected());
    recovery.note_proxy_apply_success(&slice);
    assert!(!recovery.is_rejected());

    // Newer failure cancels an older pending success.
    recovery.mark_rejected();
    let older_pending = apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice.clone()));
    assert!(matches!(
        older_pending,
        MeshLocalReloadApply::Applied | MeshLocalReloadApply::Unchanged
    ));
    let older_epoch = recovery.pending_epoch();
    assert_ne!(older_epoch, 0);
    recovery.mark_rejected();
    assert_eq!(recovery.pending_epoch(), 0);
    recovery.note_proxy_apply_success(&slice);
    assert!(
        recovery.is_rejected(),
        "older success must not clear after a newer failure"
    );

    // Unrelated overlay / ordinary activity (different slice content) does not
    // clear a local-source failure.
    recovery.mark_rejected();
    let _ = apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice.clone()));
    let unrelated = MeshSlice {
        version: "unrelated-overlay".to_string(),
        labels: [("k".into(), "v".into())].into(),
        ..slice.clone()
    };
    recovery.note_proxy_apply_success(&unrelated);
    assert!(
        recovery.is_rejected(),
        "unrelated overlay/content must not clear local-source failure"
    );

    // Proxy rejection of the pending recovery stays degraded.
    recovery.mark_rejected();
    let _ = apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice.clone()));
    recovery.note_proxy_apply_rejection(&slice);
    assert!(recovery.is_rejected());
    assert_eq!(recovery.pending_epoch(), 0);
}

/// Rounds per concurrency regression. Each round forces one barrier-aligned
/// interleaving of a stale callback against a newer transition; the asserted
/// invariant holds in EVERY linearization, so a correct handshake can never
/// fail a round while a torn (multi-atomic, check-then-act) handshake loses the
/// invariant as soon as one round lands in its window.
const RECOVERY_RACE_ROUNDS: usize = 512;

#[test]
fn concurrent_newer_rejection_and_stale_success_keep_local_source_health_degraded() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::MeshLocalSourceRecovery;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Barrier};

    let path = write_temp("yaml", VALID_MESH_YAML);
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();

    // Race A: an older `note_proxy_apply_success` for the pending candidate runs
    // concurrently with a NEWER `mark_rejected`. Both linearizations end
    // degraded:
    //   * rejection first — the now-stale success must not clear;
    //   * success first  — it clears, then the newer rejection raises again.
    // So `config_rejected` is true after every round, and no pending recovery
    // survives. Without one transition authority the success's clear can land
    // after the rejection and health silently reports healthy.
    for round in 0..RECOVERY_RACE_ROUNDS {
        let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));
        recovery.mark_rejected();
        assert!(
            recovery.mark_slice_recovery_pending(&slice).is_some(),
            "round {round}: candidate must become pending"
        );

        let barrier = Arc::new(Barrier::new(2));
        let success = {
            let recovery = Arc::clone(&recovery);
            let barrier = Arc::clone(&barrier);
            let slice = slice.clone();
            std::thread::spawn(move || {
                barrier.wait();
                recovery.note_proxy_apply_success(&slice);
            })
        };
        let rejection = {
            let recovery = Arc::clone(&recovery);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                recovery.mark_rejected();
            })
        };
        success.join().expect("success callback thread");
        rejection.join().expect("rejection thread");

        assert!(
            recovery.is_rejected(),
            "round {round}: a stale success must never clear health after a newer failure"
        );
        assert_eq!(
            recovery.pending_epoch(),
            0,
            "round {round}: a newer failure must leave no pending recovery"
        );
    }
}

#[test]
fn concurrent_stale_rejection_and_newer_candidate_keep_the_newer_recovery() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::MeshLocalSourceRecovery;
    use ferrum_edge::modes::mesh::slice::MeshSlice;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Barrier};

    let path = write_temp("yaml", VALID_MESH_YAML);
    let older = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();
    // Distinct CONTENT (not just `version`, which the content digest clears).
    let newer = MeshSlice {
        labels: [("recovery-race".to_string(), "newer".to_string())].into(),
        ..older.clone()
    };

    // Race B: an older `note_proxy_apply_rejection` carrying the OLD pending
    // identity runs concurrently with a NEWER candidate becoming pending. Both
    // linearizations leave the newer recovery outstanding and clearable:
    //   * candidate first — the stale rejection's identity no longer matches
    //     the pending slot, so it cancels nothing;
    //   * rejection first — it cancels the old pending, then the newer
    //     candidate installs its own.
    // A torn handshake tests the old identity and then cancels unconditionally,
    // wiping the newer recovery so it can never clear health again.
    for round in 0..RECOVERY_RACE_ROUNDS {
        let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));
        recovery.mark_rejected();
        assert!(
            recovery.mark_slice_recovery_pending(&older).is_some(),
            "round {round}: older candidate must become pending"
        );

        let barrier = Arc::new(Barrier::new(2));
        let rejection = {
            let recovery = Arc::clone(&recovery);
            let barrier = Arc::clone(&barrier);
            let older = older.clone();
            std::thread::spawn(move || {
                barrier.wait();
                recovery.note_proxy_apply_rejection(&older);
            })
        };
        let candidate = {
            let recovery = Arc::clone(&recovery);
            let barrier = Arc::clone(&barrier);
            let newer = newer.clone();
            std::thread::spawn(move || {
                barrier.wait();
                recovery.mark_slice_recovery_pending(&newer)
            })
        };
        rejection.join().expect("rejection callback thread");
        assert!(
            candidate
                .join()
                .expect("candidate thread")
                .is_some_and(|epoch| epoch != 0),
            "round {round}: the newer candidate must always become pending"
        );

        assert_ne!(
            recovery.pending_epoch(),
            0,
            "round {round}: a stale rejection must not cancel a newer pending recovery"
        );
        // The surviving pending recovery is the NEWER one: accepting exactly it
        // clears sticky health in both linearizations.
        recovery.note_proxy_apply_success(&newer);
        assert!(
            !recovery.is_rejected(),
            "round {round}: proxy acceptance of the newer recovery must clear health"
        );
        assert_eq!(
            recovery.pending_epoch(),
            0,
            "round {round}: the clear consumes the pending recovery"
        );
    }
}

#[test]
fn stock_policy_recovery_pending_until_bound_slice_proxy_accept() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::{
        MeshLocalReloadApply, MeshLocalSourceRecovery,
    };
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::{
        StockPolicySnapshot, apply_stock_policy_reload_candidate, load_stock_policy_baseline,
    };
    use ferrum_edge::modes::mesh::slice::MeshSlice;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    const VALID_STOCK_POLICY_YAML: &str = r#"
version: "1"
mesh:
  peer_authentications:
    - name: strict-default
      namespace: ferrum
      mtls_mode: strict
"#;
    let path = write_temp("yaml", VALID_STOCK_POLICY_YAML);
    let baseline = load_stock_policy_baseline(&path).expect("policy baseline");
    let (tx, _rx) =
        tokio::sync::watch::channel(StockPolicySnapshot::initial(Arc::new(baseline.clone())));
    let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));

    let rejected = apply_stock_policy_reload_candidate(
        &tx,
        &recovery,
        load_stock_policy_baseline(std::path::Path::new("/nonexistent/stock-policy.yaml")),
    );
    assert_eq!(rejected, MeshLocalReloadApply::Rejected);
    assert!(recovery.is_rejected());

    let recovered = apply_stock_policy_reload_candidate(&tx, &recovery, Ok(baseline.clone()));
    assert_eq!(recovered, MeshLocalReloadApply::Unchanged);
    assert!(
        recovery.is_rejected(),
        "channel send must not clear config_rejected"
    );
    assert_ne!(recovery.pending_epoch(), 0);

    // Rebuild failure leaves/sets degraded and cancels pending clear.
    recovery.mark_rejected();
    assert_eq!(recovery.pending_epoch(), 0);

    let again = apply_stock_policy_reload_candidate(&tx, &recovery, Ok(baseline));
    assert_eq!(again, MeshLocalReloadApply::Unchanged);
    let bound = MeshSlice {
        version: "stock-recovery".to_string(),
        ..MeshSlice::default()
    };
    let epoch = recovery.pending_epoch();
    recovery.bind_installed_slice_if_policy_recovery(epoch, &bound);
    recovery.note_proxy_apply_success(&bound);
    assert!(!recovery.is_rejected());
}

#[test]
fn stock_policy_recovery_epoch_fences_stale_slice_binding() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::MeshLocalSourceRecovery;
    use ferrum_edge::modes::mesh::slice::MeshSlice;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));
    recovery.mark_rejected();
    let stale_epoch = recovery.begin_policy_recovery();
    let current_epoch = recovery.begin_policy_recovery();
    let stale = MeshSlice {
        labels: [("policy".to_string(), "stale".to_string())].into(),
        ..MeshSlice::default()
    };
    let current = MeshSlice {
        labels: [("policy".to_string(), "current".to_string())].into(),
        ..MeshSlice::default()
    };

    recovery.note_proxy_apply_rejection(&stale);
    assert_eq!(
        recovery.pending_epoch(),
        current_epoch,
        "an older apply rejection must not cancel an unbound newer policy recovery"
    );

    recovery.bind_installed_slice_if_policy_recovery(stale_epoch, &stale);
    recovery.note_proxy_apply_success(&stale);
    assert!(
        recovery.is_rejected(),
        "a stale policy slice must not clear the newer recovery"
    );
    assert_eq!(recovery.pending_epoch(), current_epoch);

    recovery.bind_installed_slice_if_policy_recovery(current_epoch, &current);
    recovery.note_proxy_apply_success(&current);
    assert!(!recovery.is_rejected());
}

#[test]
fn stock_policy_reload_without_consumer_fails_closed() {
    use ferrum_edge::modes::mesh::config::MeshConfig;
    use ferrum_edge::modes::mesh::config_consumer::file_source::{
        MeshLocalReloadApply, MeshLocalSourceRecovery,
    };
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::{
        StockPolicySnapshot, apply_stock_policy_reload_candidate,
    };
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let baseline = MeshConfig::default();
    let (tx, rx) =
        tokio::sync::watch::channel(StockPolicySnapshot::initial(Arc::new(baseline.clone())));
    drop(rx);
    let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));

    let outcome = apply_stock_policy_reload_candidate(&tx, &recovery, Ok(baseline));
    assert_eq!(outcome, MeshLocalReloadApply::Rejected);
    assert!(recovery.is_rejected());
    assert_eq!(
        recovery.pending_epoch(),
        0,
        "an undeliverable policy must not leave a recovery that can later clear"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn off_thread_mesh_and_stock_loaders_keep_tokio_heartbeat_alive() {
    // Behavioral replacement for source-string wiring checks: both off-thread
    // loaders must leave the Tokio runtime free to make progress.
    use ferrum_edge::modes::mesh::config_consumer::file_source::load_mesh_slice_from_file_off_thread;
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::load_stock_policy_baseline_off_thread;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let mesh_path = write_temp("yaml", VALID_MESH_YAML);
    let stock_yaml = r#"
version: "1"
mesh:
  peer_authentications:
    - name: strict-default
      namespace: ferrum
      mtls_mode: strict
"#;
    let stock_path = write_temp("yaml", stock_yaml);

    let heartbeat = Arc::new(AtomicBool::new(false));
    let beat = heartbeat.clone();
    let ticker = tokio::spawn(async move {
        loop {
            beat.store(true, Ordering::SeqCst);
            tokio::task::yield_now().await;
        }
    });

    let mesh_load = tokio::spawn(load_mesh_slice_from_file_off_thread(
        mesh_path.to_path_buf(),
        request_for_namespace("ferrum"),
    ));
    let stock_load = tokio::spawn(load_stock_policy_baseline_off_thread(
        stock_path.to_path_buf(),
    ));

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !heartbeat.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Tokio heartbeat must advance while off-thread loads run");

    mesh_load.await.expect("join").expect("mesh load");
    stock_load.await.expect("join").expect("stock load");
    ticker.abort();
    let _ = ticker.await;
}

#[cfg(unix)]
#[test]
fn failed_reload_retains_last_good_slice() {
    use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mesh.yaml");
    std::fs::write(&path, VALID_MESH_YAML).unwrap();
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();
    let state = MeshRuntimeState::new();
    state.install_slice(slice);
    let before = state
        .snapshot()
        .as_ref()
        .as_ref()
        .cloned()
        .expect("installed");
    assert_eq!(before.services.len(), 1);

    // Replace with invalid content; a subsequent load fails while the installed
    // generation remains the last accepted slice.
    std::fs::write(&path, "mesh: {").unwrap();
    let err = load_mesh_slice_from_file(&path, request_for_namespace("ferrum"))
        .expect_err("invalid reload candidate");
    assert!(
        err.to_string()
            .contains("invalid mesh configuration document")
    );
    let after = state
        .snapshot()
        .as_ref()
        .as_ref()
        .cloned()
        .expect("retained");
    assert!(
        before.content_eq(&after),
        "failed reload must retain the complete prior mesh slice"
    );

    // Recovery without restart.
    std::fs::write(&path, VALID_MESH_YAML).unwrap();
    let recovered = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();
    state.install_slice(recovered);
    assert_eq!(
        state.snapshot().as_ref().as_ref().unwrap().services.len(),
        1
    );
}

// ── Real reload-loop coverage (issue #3776) ─────────────────────────────────
//
// `run_mesh_local_reload_loop` IS the production state machine: both
// `start_mesh_file_source_with_shutdown` and
// `start_stock_policy_watcher_with_shutdown` delegate to it, differing only in
// their notifier (SIGHUP), loader, and apply step. These tests drive that exact
// loop through its injected-notifier seam so coalescing, generation fencing,
// shutdown, and fail-closed retention are proven on the code that runs in
// production rather than on a stand-in helper.

mod reload_loop {
    use super::{VALID_MESH_YAML, request_for_namespace};

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use ferrum_edge::modes::mesh::config::MeshConfig;
    use ferrum_edge::modes::mesh::config_consumer::file_source::{
        MESH_FILE_RELOAD_MESSAGES, MeshLocalReloadResult, MeshLocalSourceRecovery,
        apply_mesh_file_reload_candidate, load_mesh_slice_from_file, run_mesh_local_reload_loop,
        spawn_mesh_reload,
    };
    use ferrum_edge::modes::mesh::config_consumer::stock_xds_client::{
        STOCK_POLICY_RELOAD_MESSAGES, StockPolicySnapshot, apply_stock_policy_reload_candidate,
        load_stock_policy_baseline, spawn_stock_policy_reload,
    };
    use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;

    const SECOND_MESH_YAML: &str = r#"
version: "1"
mesh:
  services:
    - name: renamed-after-reload
      namespace: ferrum
      ports:
        - port: 80
          protocol: http
"#;

    const POLICY_YAML: &str = r#"
version: "1"
mesh:
  peer_authentications:
    - name: strict-default
      namespace: ferrum
      mtls_mode: strict
"#;

    const SECOND_POLICY_YAML: &str = r#"
version: "1"
mesh:
  peer_authentications:
    - name: renamed-after-reload
      namespace: ferrum
      mtls_mode: strict
"#;

    /// Name of the single `PeerAuthentication` the published baseline carries.
    fn published_policy_name(snapshot: &StockPolicySnapshot) -> String {
        snapshot
            .mesh()
            .peer_authentications
            .first()
            .map(|policy| policy.name.clone())
            .unwrap_or_default()
    }

    /// A one-shot latch the first in-flight blocking load parks on, so the test
    /// can hold exactly one generation in flight while notifications pile up.
    #[derive(Default)]
    struct Gate {
        released: Mutex<bool>,
        signal: Condvar,
    }

    impl Gate {
        fn wait(&self) {
            let mut released = self.released.lock().unwrap();
            while !*released {
                released = self.signal.wait(released).unwrap();
            }
        }

        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.signal.notify_all();
        }

        /// Block the CALLER (deliberately, including a current-thread runtime
        /// worker) until released or the deadline passes.
        fn wait_timeout(&self, timeout: Duration) -> bool {
            let released = self.released.lock().unwrap();
            let (released, result) = self
                .signal
                .wait_timeout_while(released, timeout, |released| !*released)
                .unwrap();
            *released && !result.timed_out()
        }
    }

    fn write(path: &std::path::Path, body: &str) {
        std::fs::write(path, body).expect("write mesh document");
    }

    /// Poll `condition` until it holds or the deadline expires. Used instead of
    /// fixed sleeps so the tests observe real loop progress.
    async fn wait_until(label: &str, mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for: {label}"));
    }

    // ── localized `file` mesh source ────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_loop_coalesces_rapid_notifications_and_the_final_document_wins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mesh.yaml");
        write(&path, VALID_MESH_YAML);
        let path_str = path.to_string_lossy().to_string();

        let state = MeshRuntimeState::new();
        state.install_slice(
            load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap(),
        );
        let flag = Arc::new(AtomicBool::new(false));
        let recovery = MeshLocalSourceRecovery::new(flag.clone());

        let (notify_tx, notify_rx) = tokio::sync::mpsc::channel::<()>(16);
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let spawns = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Gate::default());

        let loop_task = {
            let (path_str, state, recovery) = (path_str.clone(), state.clone(), recovery.clone());
            let (spawns, gate) = (spawns.clone(), gate.clone());
            tokio::spawn(async move {
                let spawn_path = path_str.clone();
                run_mesh_local_reload_loop(
                    notify_rx,
                    &mut shutdown_rx,
                    &path_str,
                    &recovery,
                    &MESH_FILE_RELOAD_MESSAGES,
                    || {
                        // Hold ONLY the first generation in flight; every later
                        // generation goes through the production spawn helper.
                        if spawns.fetch_add(1, Ordering::SeqCst) == 0 {
                            let gate = gate.clone();
                            let load_path = spawn_path.clone();
                            tokio::task::spawn_blocking(move || {
                                gate.wait();
                                load_mesh_slice_from_file(
                                    std::path::Path::new(&load_path),
                                    request_for_namespace("ferrum"),
                                )
                            })
                        } else {
                            spawn_mesh_reload(&spawn_path, request_for_namespace("ferrum"))
                        }
                    },
                    |slice| MeshLocalReloadResult {
                        version: Some(slice.version.clone()),
                        apply: apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice)),
                    },
                )
                .await;
            })
        };

        // Generation 1 is now parked in the blocking pool.
        notify_tx.send(()).await.unwrap();
        wait_until("first generation in flight", || {
            spawns.load(Ordering::SeqCst) == 1
        })
        .await;

        // Rewrite the document, then deliver a burst while generation 1 is
        // still in flight. Waiting for the channel to drain proves the loop
        // OBSERVED every notification before the completion arm can run, so the
        // coalescing assertion below is not timing-dependent.
        write(&path, SECOND_MESH_YAML);
        for _ in 0..3 {
            notify_tx.send(()).await.unwrap();
        }
        wait_until("burst observed by the loop", || notify_tx.capacity() == 16).await;

        gate.release();

        // The stale generation-1 candidate is discarded and exactly one
        // follow-up generation runs, loading the FINAL document.
        wait_until("final document installed", || {
            state.snapshot().as_ref().as_ref().is_some_and(|slice| {
                slice
                    .services
                    .first()
                    .is_some_and(|svc| svc.name == "renamed-after-reload")
            })
        })
        .await;
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            2,
            "a burst during one in-flight load must coalesce to exactly one follow-up"
        );

        loop_task.abort();
        let _ = loop_task.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_loop_shutdown_during_an_in_flight_load_returns_without_publishing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mesh.yaml");
        write(&path, VALID_MESH_YAML);
        let path_str = path.to_string_lossy().to_string();

        let state = MeshRuntimeState::new();
        let baseline = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();
        state.install_slice(baseline.clone());
        let flag = Arc::new(AtomicBool::new(false));
        let recovery = MeshLocalSourceRecovery::new(flag.clone());

        let (notify_tx, notify_rx) = tokio::sync::mpsc::channel::<()>(4);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let spawns = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Gate::default());

        let loop_task = {
            let (path_str, state, recovery) = (path_str.clone(), state.clone(), recovery.clone());
            let (spawns, gate) = (spawns.clone(), gate.clone());
            tokio::spawn(async move {
                let spawn_path = path_str.clone();
                run_mesh_local_reload_loop(
                    notify_rx,
                    &mut shutdown_rx,
                    &path_str,
                    &recovery,
                    &MESH_FILE_RELOAD_MESSAGES,
                    || {
                        spawns.fetch_add(1, Ordering::SeqCst);
                        let gate = gate.clone();
                        let load_path = spawn_path.clone();
                        tokio::task::spawn_blocking(move || {
                            gate.wait();
                            load_mesh_slice_from_file(
                                std::path::Path::new(&load_path),
                                request_for_namespace("ferrum"),
                            )
                        })
                    },
                    |slice| MeshLocalReloadResult {
                        version: Some(slice.version.clone()),
                        apply: apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice)),
                    },
                )
                .await;
            })
        };

        notify_tx.send(()).await.unwrap();
        wait_until("load in flight", || spawns.load(Ordering::SeqCst) == 1).await;

        // A different, perfectly VALID document: if the loop awaited the
        // started blocking job (or let a late completion publish), this content
        // would become live.
        write(&path, SECOND_MESH_YAML);
        shutdown_tx.send(true).unwrap();

        // Shutdown must NOT wait for the non-cancellable blocking job.
        tokio::time::timeout(Duration::from_secs(5), loop_task)
            .await
            .expect("shutdown must not await a started blocking load")
            .expect("reload loop task");

        gate.release();
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(
            state
                .snapshot()
                .as_ref()
                .as_ref()
                .expect("baseline retained")
                .content_eq(&baseline),
            "a load completing after shutdown must never publish"
        );
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_loop_invalid_candidate_retains_last_good_and_raises_config_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mesh.yaml");
        write(&path, VALID_MESH_YAML);
        let path_str = path.to_string_lossy().to_string();

        let state = MeshRuntimeState::new();
        let baseline = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();
        state.install_slice(baseline.clone());
        let flag = Arc::new(AtomicBool::new(false));
        let recovery = MeshLocalSourceRecovery::new(flag.clone());

        let (notify_tx, notify_rx) = tokio::sync::mpsc::channel::<()>(4);
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let loop_task = {
            let (path_str, state, recovery) = (path_str.clone(), state.clone(), recovery.clone());
            tokio::spawn(async move {
                let spawn_path = path_str.clone();
                run_mesh_local_reload_loop(
                    notify_rx,
                    &mut shutdown_rx,
                    &path_str,
                    &recovery,
                    &MESH_FILE_RELOAD_MESSAGES,
                    || spawn_mesh_reload(&spawn_path, request_for_namespace("ferrum")),
                    |slice| MeshLocalReloadResult {
                        version: Some(slice.version.clone()),
                        apply: apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice)),
                    },
                )
                .await;
            })
        };

        write(&path, "mesh: {");
        notify_tx.send(()).await.unwrap();
        wait_until("rejection observed", || flag.load(Ordering::SeqCst)).await;
        assert!(
            state
                .snapshot()
                .as_ref()
                .as_ref()
                .expect("last-good retained")
                .content_eq(&baseline),
            "an invalid candidate must retain the last-good slice"
        );

        // Recovery still requires proxy acceptance of the exact candidate.
        write(&path, VALID_MESH_YAML);
        notify_tx.send(()).await.unwrap();
        wait_until("recovery candidate pending", || {
            recovery.pending_epoch() != 0
        })
        .await;
        assert!(
            flag.load(Ordering::SeqCst),
            "a provisional install must not clear sticky health"
        );
        let live = state
            .snapshot()
            .as_ref()
            .as_ref()
            .cloned()
            .expect("candidate installed");
        recovery.note_proxy_apply_success(&live);
        assert!(!flag.load(Ordering::SeqCst));

        loop_task.abort();
        let _ = loop_task.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn file_loop_shutdown_wins_a_simultaneously_ready_completion() {
        // On a current-thread runtime the loop task is only polled when this
        // test awaits. Arming shutdown and finishing the load while the task is
        // unpolled makes both select arms ready at the SAME poll, which is the
        // exact tie the `biased;` shutdown-first ordering exists to resolve.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mesh.yaml");
        write(&path, VALID_MESH_YAML);
        let path_str = path.to_string_lossy().to_string();

        let state = MeshRuntimeState::new();
        let baseline = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();
        state.install_slice(baseline.clone());
        let flag = Arc::new(AtomicBool::new(false));
        let recovery = MeshLocalSourceRecovery::new(flag.clone());

        let (notify_tx, notify_rx) = tokio::sync::mpsc::channel::<()>(4);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let spawns = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Gate::default());
        let finished = Arc::new(Gate::default());

        let loop_task = {
            let (path_str, state, recovery) = (path_str.clone(), state.clone(), recovery.clone());
            let (spawns, gate) = (spawns.clone(), gate.clone());
            let finished = finished.clone();
            tokio::spawn(async move {
                let spawn_path = path_str.clone();
                run_mesh_local_reload_loop(
                    notify_rx,
                    &mut shutdown_rx,
                    &path_str,
                    &recovery,
                    &MESH_FILE_RELOAD_MESSAGES,
                    || {
                        spawns.fetch_add(1, Ordering::SeqCst);
                        let gate = gate.clone();
                        let load_path = spawn_path.clone();
                        let finished = finished.clone();
                        tokio::task::spawn_blocking(move || {
                            gate.wait();
                            let loaded = load_mesh_slice_from_file(
                                std::path::Path::new(&load_path),
                                request_for_namespace("ferrum"),
                            );
                            finished.release();
                            loaded
                        })
                    },
                    |slice| MeshLocalReloadResult {
                        version: Some(slice.version.clone()),
                        apply: apply_mesh_file_reload_candidate(&state, &recovery, Ok(slice)),
                    },
                )
                .await;
            })
        };

        notify_tx.send(()).await.unwrap();
        wait_until("load in flight", || spawns.load(Ordering::SeqCst) == 1).await;

        // A valid but DIFFERENT document, so publishing would be observable.
        write(&path, SECOND_MESH_YAML);

        // From here on the test performs no `.await`, so the loop task cannot
        // be polled until both arms are armed.
        shutdown_tx.send(true).unwrap();
        gate.release();
        assert!(
            finished.wait_timeout(Duration::from_secs(10)),
            "blocking load must complete while the loop is unpolled"
        );

        tokio::time::timeout(Duration::from_secs(5), loop_task)
            .await
            .expect("loop returns on the tied poll")
            .expect("reload loop task");

        assert!(
            state
                .snapshot()
                .as_ref()
                .as_ref()
                .expect("baseline retained")
                .content_eq(&baseline),
            "a completion tied with shutdown must not publish"
        );
        assert!(!flag.load(Ordering::SeqCst));
    }

    // ── `stock_xds` policy watcher ──────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stock_policy_loop_coalesces_rapid_notifications_and_the_final_document_wins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        write(&path, POLICY_YAML);
        let path_str = path.to_string_lossy().to_string();

        let baseline = load_stock_policy_baseline(&path).expect("policy baseline");
        let (policy_tx, _policy_rx) =
            tokio::sync::watch::channel(StockPolicySnapshot::initial(Arc::new(baseline)));
        let flag = Arc::new(AtomicBool::new(false));
        let recovery = MeshLocalSourceRecovery::new(flag.clone());

        let (notify_tx, notify_rx) = tokio::sync::mpsc::channel::<()>(16);
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let spawns = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Gate::default());
        let observed = policy_tx.subscribe();

        let loop_task = {
            let (path_str, recovery) = (path_str.clone(), recovery.clone());
            let (spawns, gate) = (spawns.clone(), gate.clone());
            tokio::spawn(async move {
                let spawn_path = path_str.clone();
                run_mesh_local_reload_loop(
                    notify_rx,
                    &mut shutdown_rx,
                    &path_str,
                    &recovery,
                    &STOCK_POLICY_RELOAD_MESSAGES,
                    || {
                        if spawns.fetch_add(1, Ordering::SeqCst) == 0 {
                            let gate = gate.clone();
                            let load_path = spawn_path.clone();
                            tokio::task::spawn_blocking(move || {
                                gate.wait();
                                load_stock_policy_baseline(std::path::Path::new(&load_path))
                            })
                        } else {
                            spawn_stock_policy_reload(&spawn_path)
                        }
                    },
                    |mesh: MeshConfig| MeshLocalReloadResult {
                        version: None,
                        apply: apply_stock_policy_reload_candidate(&policy_tx, &recovery, Ok(mesh)),
                    },
                )
                .await;
            })
        };

        notify_tx.send(()).await.unwrap();
        wait_until("first generation in flight", || {
            spawns.load(Ordering::SeqCst) == 1
        })
        .await;

        write(&path, SECOND_POLICY_YAML);
        for _ in 0..3 {
            notify_tx.send(()).await.unwrap();
        }
        wait_until("burst observed by the loop", || notify_tx.capacity() == 16).await;

        gate.release();

        wait_until("final policy published", || {
            published_policy_name(&observed.borrow()) == "renamed-after-reload"
        })
        .await;
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            2,
            "a burst during one in-flight load must coalesce to exactly one follow-up"
        );

        loop_task.abort();
        let _ = loop_task.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stock_policy_loop_shutdown_during_an_in_flight_load_returns_without_publishing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        write(&path, POLICY_YAML);
        let path_str = path.to_string_lossy().to_string();

        let baseline = load_stock_policy_baseline(&path).expect("policy baseline");
        let (policy_tx, _policy_rx) =
            tokio::sync::watch::channel(StockPolicySnapshot::initial(Arc::new(baseline)));
        let flag = Arc::new(AtomicBool::new(false));
        let recovery = MeshLocalSourceRecovery::new(flag.clone());
        let observed = policy_tx.subscribe();

        let (notify_tx, notify_rx) = tokio::sync::mpsc::channel::<()>(4);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let spawns = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Gate::default());

        let loop_task = {
            let (path_str, recovery) = (path_str.clone(), recovery.clone());
            let (spawns, gate) = (spawns.clone(), gate.clone());
            tokio::spawn(async move {
                let spawn_path = path_str.clone();
                run_mesh_local_reload_loop(
                    notify_rx,
                    &mut shutdown_rx,
                    &path_str,
                    &recovery,
                    &STOCK_POLICY_RELOAD_MESSAGES,
                    || {
                        spawns.fetch_add(1, Ordering::SeqCst);
                        let gate = gate.clone();
                        let load_path = spawn_path.clone();
                        tokio::task::spawn_blocking(move || {
                            gate.wait();
                            load_stock_policy_baseline(std::path::Path::new(&load_path))
                        })
                    },
                    |mesh: MeshConfig| MeshLocalReloadResult {
                        version: None,
                        apply: apply_stock_policy_reload_candidate(&policy_tx, &recovery, Ok(mesh)),
                    },
                )
                .await;
            })
        };

        notify_tx.send(()).await.unwrap();
        wait_until("load in flight", || spawns.load(Ordering::SeqCst) == 1).await;

        write(&path, SECOND_POLICY_YAML);
        shutdown_tx.send(true).unwrap();

        tokio::time::timeout(Duration::from_secs(5), loop_task)
            .await
            .expect("shutdown must not await a started blocking load")
            .expect("reload loop task");

        gate.release();
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(
            published_policy_name(&observed.borrow()),
            "strict-default",
            "a load completing after shutdown must never publish a new baseline"
        );
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stock_policy_loop_invalid_candidate_retains_last_good_and_raises_config_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        write(&path, POLICY_YAML);
        let path_str = path.to_string_lossy().to_string();

        let baseline = load_stock_policy_baseline(&path).expect("policy baseline");
        let (policy_tx, _policy_rx) =
            tokio::sync::watch::channel(StockPolicySnapshot::initial(Arc::new(baseline)));
        let flag = Arc::new(AtomicBool::new(false));
        let recovery = MeshLocalSourceRecovery::new(flag.clone());
        let observed = policy_tx.subscribe();

        let (notify_tx, notify_rx) = tokio::sync::mpsc::channel::<()>(4);
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let loop_task = {
            let (path_str, recovery) = (path_str.clone(), recovery.clone());
            tokio::spawn(async move {
                let spawn_path = path_str.clone();
                run_mesh_local_reload_loop(
                    notify_rx,
                    &mut shutdown_rx,
                    &path_str,
                    &recovery,
                    &STOCK_POLICY_RELOAD_MESSAGES,
                    || spawn_stock_policy_reload(&spawn_path),
                    |mesh: MeshConfig| MeshLocalReloadResult {
                        version: None,
                        apply: apply_stock_policy_reload_candidate(&policy_tx, &recovery, Ok(mesh)),
                    },
                )
                .await;
            })
        };

        write(&path, "mesh: {");
        notify_tx.send(()).await.unwrap();
        wait_until("rejection observed", || flag.load(Ordering::SeqCst)).await;
        assert_eq!(
            published_policy_name(&observed.borrow()),
            "strict-default",
            "an invalid candidate must retain the last-good policy baseline"
        );
        assert_eq!(
            recovery.pending_epoch(),
            0,
            "a rejected candidate must leave no recovery that could later clear"
        );

        // A valid candidate publishes and marks recovery pending, but only the
        // proxy apply lifecycle may clear sticky health.
        write(&path, SECOND_POLICY_YAML);
        notify_tx.send(()).await.unwrap();
        wait_until("recovery candidate pending", || {
            recovery.pending_epoch() != 0
        })
        .await;
        assert!(
            flag.load(Ordering::SeqCst),
            "a channel send must not clear sticky health"
        );

        loop_task.abort();
        let _ = loop_task.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stock_policy_loop_shutdown_wins_a_simultaneously_ready_completion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        write(&path, POLICY_YAML);
        let path_str = path.to_string_lossy().to_string();

        let baseline = load_stock_policy_baseline(&path).expect("policy baseline");
        let (policy_tx, _policy_rx) =
            tokio::sync::watch::channel(StockPolicySnapshot::initial(Arc::new(baseline)));
        let flag = Arc::new(AtomicBool::new(false));
        let recovery = MeshLocalSourceRecovery::new(flag.clone());
        let observed = policy_tx.subscribe();

        let (notify_tx, notify_rx) = tokio::sync::mpsc::channel::<()>(4);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let spawns = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Gate::default());
        let finished = Arc::new(Gate::default());

        let loop_task = {
            let (path_str, recovery) = (path_str.clone(), recovery.clone());
            let (spawns, gate) = (spawns.clone(), gate.clone());
            let finished = finished.clone();
            tokio::spawn(async move {
                let spawn_path = path_str.clone();
                run_mesh_local_reload_loop(
                    notify_rx,
                    &mut shutdown_rx,
                    &path_str,
                    &recovery,
                    &STOCK_POLICY_RELOAD_MESSAGES,
                    || {
                        spawns.fetch_add(1, Ordering::SeqCst);
                        let gate = gate.clone();
                        let load_path = spawn_path.clone();
                        let finished = finished.clone();
                        tokio::task::spawn_blocking(move || {
                            gate.wait();
                            let loaded =
                                load_stock_policy_baseline(std::path::Path::new(&load_path));
                            finished.release();
                            loaded
                        })
                    },
                    |mesh: MeshConfig| MeshLocalReloadResult {
                        version: None,
                        apply: apply_stock_policy_reload_candidate(&policy_tx, &recovery, Ok(mesh)),
                    },
                )
                .await;
            })
        };

        notify_tx.send(()).await.unwrap();
        wait_until("load in flight", || spawns.load(Ordering::SeqCst) == 1).await;

        write(&path, SECOND_POLICY_YAML);

        shutdown_tx.send(true).unwrap();
        gate.release();
        assert!(
            finished.wait_timeout(Duration::from_secs(10)),
            "blocking load must complete while the loop is unpolled"
        );

        tokio::time::timeout(Duration::from_secs(5), loop_task)
            .await
            .expect("loop returns on the tied poll")
            .expect("reload loop task");

        assert_eq!(
            published_policy_name(&observed.borrow()),
            "strict-default",
            "a completion tied with shutdown must not publish"
        );
        assert!(!flag.load(Ordering::SeqCst));
    }
}

// ── Recovery-transition atomicity and no-pending short circuits (#3776) ─────

#[test]
fn mark_rejected_if_pending_is_one_transition_and_ignores_a_cleared_slot() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::MeshLocalSourceRecovery;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let path = write_temp("yaml", VALID_MESH_YAML);
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();

    // No pending recovery: the helper must NOT raise sticky health. The old
    // `pending_epoch() != 0` + `mark_rejected()` pair could observe a pending
    // slot, lose it to a concurrent accept, and then raise anyway.
    let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));
    assert!(!recovery.mark_rejected_if_pending());
    assert!(
        !recovery.is_rejected(),
        "an already-cleared pending slot must not raise config_rejected"
    );

    // A pending recovery that is accepted before the callback runs is likewise
    // no longer rejectable.
    recovery.mark_rejected();
    assert!(recovery.mark_slice_recovery_pending(&slice).is_some());
    recovery.note_proxy_apply_success(&slice);
    assert!(!recovery.is_rejected());
    assert_eq!(recovery.pending_epoch(), 0);
    assert!(!recovery.mark_rejected_if_pending());
    assert!(!recovery.is_rejected());

    // Still pending: the helper raises and consumes the pending slot.
    assert!(recovery.mark_slice_recovery_pending(&slice).is_some());
    assert!(recovery.mark_rejected_if_pending());
    assert!(recovery.is_rejected());
    assert_eq!(
        recovery.pending_epoch(),
        0,
        "raising rejection cancels the pending clear in the same transition"
    );
}

#[test]
fn apply_callbacks_with_no_relevant_pending_recovery_are_no_ops() {
    // The early-return contract behind the hot-path recovery work: with no
    // pending recovery (or an unbound policy recovery), a proxy accept/reject
    // or a policy bind must leave health and the pending slot exactly as found.
    use ferrum_edge::modes::mesh::config_consumer::file_source::MeshLocalSourceRecovery;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let path = write_temp("yaml", VALID_MESH_YAML);
    let slice = load_mesh_slice_from_file(&path, request_for_namespace("ferrum")).unwrap();

    // Healthy, nothing pending.
    let recovery = MeshLocalSourceRecovery::new(Arc::new(AtomicBool::new(false)));
    recovery.note_proxy_apply_success(&slice);
    recovery.note_proxy_apply_rejection(&slice);
    recovery.bind_installed_slice_if_policy_recovery(1, &slice);
    assert!(!recovery.is_rejected());
    assert_eq!(recovery.pending_epoch(), 0);

    // Degraded, nothing pending: an unrelated accepted slice must not clear.
    recovery.mark_rejected();
    recovery.note_proxy_apply_success(&slice);
    assert!(recovery.is_rejected());
    assert_eq!(recovery.pending_epoch(), 0);

    // Unbound policy recovery: no digest is bound yet, so neither an apply
    // rejection nor a bind for a DIFFERENT epoch may touch it.
    let epoch = recovery.begin_policy_recovery();
    assert_ne!(epoch, 0);
    recovery.note_proxy_apply_rejection(&slice);
    assert_eq!(
        recovery.pending_epoch(),
        epoch,
        "an unbound policy recovery is not cancelable by an older apply callback"
    );
    recovery.bind_installed_slice_if_policy_recovery(epoch.wrapping_add(1), &slice);
    assert_eq!(
        recovery.pending_epoch(),
        epoch,
        "a bind for another epoch must leave the pending slot untouched"
    );

    // The matching bind does take effect, and only then can the exact slice
    // clear sticky health.
    recovery.bind_installed_slice_if_policy_recovery(epoch, &slice);
    recovery.note_proxy_apply_success(&slice);
    assert!(!recovery.is_rejected());
    assert_eq!(recovery.pending_epoch(), 0);
}
