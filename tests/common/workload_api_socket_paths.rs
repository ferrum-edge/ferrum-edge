//! Socket paths the production Workload API ancestor policy actually admits.
//!
//! `WorkloadApiSocketConfig::validate` refuses a socket whose path crosses a
//! symlinked directory, and it refuses one whose parent leaves no room for the
//! private staging directory the listener binds inside. Both refusals are
//! correct, and both are easy for a fixture to trip on before it exercises any
//! identity behaviour:
//!
//! - the ordinary macOS `TMPDIR` is `/var/folders/…`, and `/var` is a symlink
//!   to `private/var`, so a raw [`std::env::temp_dir`] path is refused outright
//!   ("directory '/var' on the socket path is a symlink");
//! - the *canonical* form of that same directory is ~56 bytes, which leaves
//!   under twenty bytes inside `sockaddr_un.sun_path` once the staging suffix
//!   is reserved, so a long per-test directory name is refused too.
//!
//! These helpers resolve a canonical base that has room to spare and hand out
//! short paths beneath it. They deliberately do **not** relax anything: the
//! production policy is what decides, and the dedicated negative fixtures that
//! build intentionally unsafe ancestors keep using it (issue #4984).
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

/// Longest socket path the listener accepts, restated from its private
/// `MAX_SOCKET_PATH_BYTES`: `sockaddr_un.sun_path` is 104 bytes on macOS and
/// 108 on Linux, and `bind(2)` reports a bare `EINVAL` past it.
const MAX_SOCKET_PATH_BYTES: usize = 100;

/// Longest socket *parent* the listener accepts, because the socket is bound at
/// `<parent>/.fw-<pid>-<seq>/s` and published from there.
const MAX_SOCKET_PARENT_BYTES: usize =
    MAX_SOCKET_PATH_BYTES - ferrum_edge::identity::workload_api::MAX_STAGING_SUFFIX_BYTES;

/// Distinguishes sockets within one test binary. Directories are per-process,
/// so this only has to be unique among concurrently running tests here.
static SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// A canonical directory that leaves `reserved` bytes of parent budget free for
/// the caller's own components.
///
/// The platform temporary directory is preferred so a runner that points
/// `TMPDIR` somewhere deliberate keeps it; `/tmp` is the fallback for a
/// temporary directory too deep to leave room. Both are canonicalized, because
/// the ancestor policy refuses a symlinked component rather than following it.
pub fn admitted_socket_base(reserved: usize) -> PathBuf {
    let mut rejected = Vec::new();
    for candidate in [std::env::temp_dir(), PathBuf::from("/tmp")] {
        let Ok(canonical) = std::fs::canonicalize(&candidate) else {
            continue;
        };
        if canonical.as_os_str().len() + reserved <= MAX_SOCKET_PARENT_BYTES {
            return canonical;
        }
        rejected.push(canonical);
    }
    panic!(
        "no temporary directory on this host leaves {reserved} bytes under the \
         {MAX_SOCKET_PARENT_BYTES}-byte Unix-socket parent budget; tried {rejected:?}. \
         Point TMPDIR at a shorter path, as in `TMPDIR=$(mktemp -d /private/tmp/fe-XXXXXX)`"
    );
}

/// The private directory every Workload API socket in this test binary lives
/// in, created once at mode 0700 and retained for the process lifetime.
///
/// Retained rather than per-test so nothing can replace the directory beneath a
/// running listener, and so a test that asserts on its parent's contents sees
/// only what the listener put there. The `chmod` doubles as the ownership
/// proof: it fails outright on a leftover directory this process does not own.
fn socket_root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        use std::os::unix::fs::PermissionsExt;

        let name = format!("fe-wl-{}", std::process::id());
        let root = admitted_socket_base(1 + name.len()).join(name);
        std::fs::create_dir_all(&root).expect("create the Workload API test socket directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 the Workload API test socket directory this process owns");
        let metadata = std::fs::symlink_metadata(&root)
            .expect("inspect the Workload API test socket directory");
        assert!(
            metadata.is_dir(),
            "the Workload API test socket directory must be a real directory, not a symlink: {}",
            root.display()
        );
        root
    })
    .as_path()
}

/// A unique socket path under [`socket_root`], short enough to bind.
pub fn workload_api_socket_path(label: &str) -> PathBuf {
    let root = socket_root();
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = format!("{label}-{sequence}.sock");
    assert!(
        root.as_os_str().len() + 1 + name.len() <= MAX_SOCKET_PATH_BYTES,
        "socket label '{label}' is too long for the {MAX_SOCKET_PATH_BYTES}-byte Unix-socket \
         limit under '{}'",
        root.display()
    );
    root.join(name)
}
