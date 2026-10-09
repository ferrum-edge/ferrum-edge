//! External coverage for the CNI installer's staged-file modes (#6126).
//!
//! Every artifact the installer publishes is written to an exclusive staging
//! file and renamed into place. Its final mode is applied through the open
//! staging handle (`fchmod`), never by path, so a symlink swapped in at a
//! staging or publish path can never redirect the mode change onto another
//! file.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ferrum_edge::cni::install::{
    CniInstallConfig, CniOwnership, OWNERSHIP_MANIFEST_FILE_NAME, install,
};
use ferrum_edge::cni::lifecycle::write_ready_marker;

const GENERATED_CONF: &str = "00-ferrum.conflist";

fn mode_of(path: &Path) -> u32 {
    let meta = fs::symlink_metadata(path).expect("stat");
    meta.permissions().mode() & 0o777
}

fn assert_staging_files_gone(dir: &Path) {
    let leftovers: Vec<_> = fs::read_dir(dir)
        .expect("read dir")
        .map(|entry| entry.expect("dir entry").file_name())
        .filter(|name| {
            let name = name.to_string_lossy();
            name.ends_with(".tmp") || name.ends_with(".install")
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "staging files left behind: {leftovers:?}"
    );
}

#[test]
fn install_publishes_each_artifact_with_its_expected_mode() {
    let root = tempfile::tempdir().expect("tempdir");
    let bin_dir = root.path().join("opt-cni-bin");
    let conf_dir = root.path().join("etc-cni-net-d");
    fs::create_dir_all(&bin_dir).expect("bin dir");
    fs::create_dir_all(&conf_dir).expect("conf dir");
    fs::write(
        conf_dir.join("10-calico.conflist"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "cniVersion": "1.0.0",
            "name": "calico",
            "plugins": [{"type": "calico", "ipam": {"type": "calico-ipam"}}]
        }))
        .expect("primary json"),
    )
    .expect("write primary");
    // The source binary's own mode must not leak into the published copy.
    let source_binary = root.path().join("image-ferrum-cni");
    fs::write(&source_binary, b"ferrum-cni v1").expect("write source binary");
    fs::set_permissions(&source_binary, fs::Permissions::from_mode(0o600))
        .expect("chmod source binary");

    let config = CniInstallConfig {
        host_bin_dir: bin_dir.display().to_string(),
        host_conf_dir: conf_dir.display().to_string(),
        host_socket_dir: root.path().join("var-run-ferrum").display().to_string(),
        conf_file_name: GENERATED_CONF.to_string(),
        chained_with: "calico".to_string(),
        socket_path: "/var/run/ferrum/node-agent-cni.sock".to_string(),
        ownership: CniOwnership {
            owner: "ferrum/mesh".to_string(),
            generation: "gen-1".to_string(),
        },
    };
    install(&config, &source_binary).expect("install");

    assert_eq!(mode_of(&bin_dir.join("ferrum-cni")), 0o755);
    assert_eq!(mode_of(&conf_dir.join(GENERATED_CONF)), 0o644);
    assert_eq!(mode_of(&conf_dir.join(OWNERSHIP_MANIFEST_FILE_NAME)), 0o600);
    assert_staging_files_gone(&bin_dir);
    assert_staging_files_gone(&conf_dir);
}

#[test]
fn a_published_file_replaces_a_planted_symlink_without_touching_its_target() {
    let root = tempfile::tempdir().expect("tempdir");
    let victim = root.path().join("victim");
    fs::write(&victim, b"do not touch").expect("write victim");
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).expect("chmod victim");
    let marker = root.path().join("cleanup-ready");
    std::os::unix::fs::symlink(&victim, &marker).expect("plant symlink");

    write_ready_marker(marker.to_str().expect("utf-8 path")).expect("publish marker");

    let published = fs::symlink_metadata(&marker).expect("marker stat");
    assert!(
        published.file_type().is_file(),
        "the publish must replace the symlink with a regular file"
    );
    assert_eq!(mode_of(&marker), 0o600);
    assert_eq!(
        mode_of(&victim),
        0o644,
        "the symlink target's mode must never be changed"
    );
    assert_eq!(
        fs::read(&victim).expect("read victim"),
        b"do not touch",
        "the symlink target's contents must never be written"
    );
    assert_staging_files_gone(root.path());
}

#[test]
fn a_republished_file_takes_its_mode_from_the_staging_handle() {
    let root = tempfile::tempdir().expect("tempdir");
    let marker = root.path().join("cleanup-ready");
    fs::write(&marker, b"stale").expect("write stale marker");
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o666)).expect("chmod stale marker");

    write_ready_marker(marker.to_str().expect("utf-8 path")).expect("publish marker");

    assert_eq!(mode_of(&marker), 0o600);
    assert_staging_files_gone(root.path());
}
