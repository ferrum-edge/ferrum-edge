//! Admission rules for Unix-domain-socket backend paths (issue #3261).
//!
//! This validator is the single fail-closed gate between an operator-authored
//! (or carrier-decoded) `unix://` endpoint and `UnixStream::connect`, so every
//! rule it enforces is pinned here — including the ones that only matter for a
//! hostile input.

use ferrum_edge::util::unix_socket::{
    MAX_UNIX_SOCKET_PATH_BYTES, UnixSocketPathRejection, admit_configured_path,
    admit_socket_for_connect, normalize_allowed_root, validate_allowed_roots,
    validate_unix_socket_path,
};

#[test]
fn admits_ordinary_absolute_socket_paths() {
    for path in [
        "/var/run/app.sock",
        "/tmp/x",
        "/run/ferrum/inner-dir/grpc.sock",
        // A dot INSIDE a component is fine; only a whole `.` / `..` component
        // is a traversal segment.
        "/var/run/app.v2.sock",
        "/var/run/..hidden.sock",
    ] {
        assert_eq!(
            validate_unix_socket_path(path),
            Ok(()),
            "{path:?} should be admitted"
        );
    }
}

#[test]
fn rejects_relative_and_abstract_paths() {
    // Relative paths resolve against the process CWD — not a reviewable
    // location. Abstract (`\0`-prefixed) and `@`-prefixed sockets are not part
    // of Istio's `defaultEndpoint` grammar and fall out of the same rule.
    for path in ["var/run/app.sock", "./app.sock", "@abstract", "app.sock"] {
        assert_eq!(
            validate_unix_socket_path(path),
            Err(UnixSocketPathRejection::NotAbsolute),
            "{path:?} must fail closed as non-absolute"
        );
    }
}

#[test]
fn rejects_traversal_components() {
    for path in [
        "/var/../etc/passwd",
        "/var/run/../../etc/shadow",
        "/var/./run/app.sock",
        "/..",
    ] {
        assert_eq!(
            validate_unix_socket_path(path),
            Err(UnixSocketPathRejection::TraversalComponent),
            "{path:?} must fail closed rather than being normalized"
        );
    }
}

#[test]
fn rejects_structurally_ambiguous_paths() {
    assert_eq!(
        validate_unix_socket_path(""),
        Err(UnixSocketPathRejection::Empty)
    );
    assert_eq!(
        validate_unix_socket_path("/var//run/app.sock"),
        Err(UnixSocketPathRejection::EmptyComponent)
    );
    // A trailing slash names a directory, never a socket. `/` is the extreme
    // case of the same rule.
    assert_eq!(
        validate_unix_socket_path("/var/run/"),
        Err(UnixSocketPathRejection::TrailingSlash)
    );
    assert_eq!(
        validate_unix_socket_path("/"),
        Err(UnixSocketPathRejection::TrailingSlash)
    );
    // Nothing is trimmed: silently trimming would dial a different path than
    // the operator wrote.
    assert_eq!(
        validate_unix_socket_path(" /var/run/app.sock"),
        Err(UnixSocketPathRejection::SurroundingWhitespace)
    );
    assert_eq!(
        validate_unix_socket_path("/var/run/app.sock\n"),
        Err(UnixSocketPathRejection::SurroundingWhitespace)
    );
}

#[test]
fn rejects_nul_and_control_characters() {
    // An interior NUL would truncate `sun_path`, so the kernel would bind/dial
    // a DIFFERENT path than the one reviewed.
    assert_eq!(
        validate_unix_socket_path("/var/run/app\u{0}.sock"),
        Err(UnixSocketPathRejection::InteriorNul)
    );
    assert_eq!(
        validate_unix_socket_path("/var/run/app\u{7}.sock"),
        Err(UnixSocketPathRejection::ControlCharacter)
    );
    // A NUL is also a control character; the NUL rule must win so the
    // diagnostic names the sharper failure.
    assert_eq!(
        validate_unix_socket_path("/\u{0}"),
        Err(UnixSocketPathRejection::InteriorNul)
    );
}

#[test]
fn enforces_the_portable_sockaddr_un_budget() {
    // 103 bytes = the usable `sun_path` budget on the SMALLEST supported
    // platform (macOS/BSD reserve 104 including the NUL; Linux allows 108), so
    // a path admitted on one platform always dials on another.
    assert_eq!(MAX_UNIX_SOCKET_PATH_BYTES, 103);
    let at_limit = format!("/{}", "a".repeat(MAX_UNIX_SOCKET_PATH_BYTES - 1));
    assert_eq!(at_limit.len(), MAX_UNIX_SOCKET_PATH_BYTES);
    assert_eq!(validate_unix_socket_path(&at_limit), Ok(()));

    let over_limit = format!("/{}", "a".repeat(MAX_UNIX_SOCKET_PATH_BYTES));
    assert_eq!(
        validate_unix_socket_path(&over_limit),
        Err(UnixSocketPathRejection::TooLong)
    );

    // The budget is in BYTES, not characters: a multi-byte path that looks
    // short must still be measured on the wire.
    let multibyte = format!("/{}", "é".repeat(60));
    assert!(multibyte.chars().count() < MAX_UNIX_SOCKET_PATH_BYTES);
    assert_eq!(
        validate_unix_socket_path(&multibyte),
        Err(UnixSocketPathRejection::TooLong)
    );
}

#[test]
fn every_rejection_reason_is_specific_and_leaks_no_path() {
    let reasons = [
        UnixSocketPathRejection::Empty,
        UnixSocketPathRejection::SurroundingWhitespace,
        UnixSocketPathRejection::NotAbsolute,
        UnixSocketPathRejection::TraversalComponent,
        UnixSocketPathRejection::EmptyComponent,
        UnixSocketPathRejection::TrailingSlash,
        UnixSocketPathRejection::InteriorNul,
        UnixSocketPathRejection::ControlCharacter,
        UnixSocketPathRejection::TooLong,
        UnixSocketPathRejection::MissingSocketPathTag,
        UnixSocketPathRejection::MissingWireProtocolTag,
        UnixSocketPathRejection::InvalidWireProtocolTag,
        UnixSocketPathRejection::ConflictingTransportTags,
        UnixSocketPathRejection::ContainmentNotConfigured,
        UnixSocketPathRejection::InvalidContainmentRoot,
        UnixSocketPathRejection::OutsideAllowedRoots,
        UnixSocketPathRejection::UnresolvablePath,
        UnixSocketPathRejection::SymlinkEscape,
        UnixSocketPathRejection::NotASocket,
        UnixSocketPathRejection::UnexpectedOwner,
        UnixSocketPathRejection::WorldWritableSocket,
        UnixSocketPathRejection::UnsafeDirectoryComponent,
        UnixSocketPathRejection::UntrustedDirectoryOwner,
        UnixSocketPathRejection::UnsafeDirectoryPermissions,
        UnixSocketPathRejection::PlatformUnsupported,
    ];
    let mut seen = std::collections::BTreeSet::new();
    for reason in reasons {
        let text = reason.reason();
        assert!(!text.is_empty());
        assert!(
            seen.insert(text),
            "reason {text:?} is not unique; a status report could not distinguish the rules"
        );
    }
}

// ── Containment allowlist (the local privilege boundary) ─────────────────────
//
// Syntax alone cannot stop a `Sidecar` from naming `/var/run/docker.sock`, so
// containment is what actually bounds which local sockets the (often
// privileged) Ferrum process will connect to. These tests pin the whole gate,
// including the default-off posture.

fn roots(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

/// The SHIPPED DEFAULT is an empty allowlist, and it must refuse everything.
/// A permissive default would silently re-open the privilege boundary for every
/// existing deployment.
#[test]
fn an_unconfigured_allowlist_refuses_every_socket_path() {
    for path in ["/var/run/app.sock", "/run/ferrum/grpc.sock", "/tmp/x.sock"] {
        assert_eq!(
            admit_configured_path(path, &[]),
            Err(UnixSocketPathRejection::ContainmentNotConfigured),
            "{path:?} must be refused when no containment roots are configured"
        );
    }
}

#[test]
fn admits_only_strict_descendants_of_a_configured_root() {
    let allowed = roots(&["/run/ferrum"]);
    for path in ["/run/ferrum/app.sock", "/run/ferrum/nested/grpc.sock"] {
        assert_eq!(
            admit_configured_path(path, &allowed),
            Ok(()),
            "{path:?} is inside the configured root"
        );
    }
    for path in [
        // A privileged socket the operator never allowed.
        "/var/run/docker.sock",
        // Prefix SIBLING: a byte-prefix check would wrongly admit this.
        "/run/ferrum-evil/app.sock",
        // The root itself names a directory, not a socket.
        "/run/ferrum",
    ] {
        assert_eq!(
            admit_configured_path(path, &allowed),
            Err(UnixSocketPathRejection::OutsideAllowedRoots),
            "{path:?} must not be admitted by root /run/ferrum"
        );
    }
}

/// A trailing slash on a configured root is tolerated (operators write both
/// forms) but nothing else is repaired, and a bare `/` is refused outright —
/// it would contain every path on the host and make the allowlist a no-op.
#[test]
fn containment_roots_are_normalized_conservatively() {
    assert_eq!(normalize_allowed_root("/run/ferrum/"), Ok("/run/ferrum"));
    assert_eq!(normalize_allowed_root("/run/ferrum"), Ok("/run/ferrum"));
    for hostile in [
        "/",
        "",
        "relative/dir",
        "/run/../etc",
        "/run//ferrum",
        " /run",
    ] {
        assert_eq!(
            normalize_allowed_root(hostile),
            Err(UnixSocketPathRejection::InvalidContainmentRoot),
            "{hostile:?} must not be usable as a containment root"
        );
    }
    assert!(validate_allowed_roots(&roots(&["/run/ferrum", "/var/run/app"])).is_ok());
    let err = validate_allowed_roots(&roots(&["/run/ferrum", "/"]))
        .expect_err("a bare '/' root must fail startup");
    assert!(
        err.contains("FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS"),
        "the startup error must name the offending setting: {err}"
    );
    let hostile = "/run/ferrum\nforged-log-record";
    let err = validate_allowed_roots(&roots(&[hostile]))
        .expect_err("a control character in a root must fail startup");
    assert!(
        !err.contains(hostile) && err.contains("entry 1"),
        "the diagnostic must identify the entry without interpolating a hostile path: {err:?}"
    );
}

/// A malformed root is a hard error, never a silently skipped entry: skipping
/// would narrow a reviewed security allowlist with no signal at all.
#[test]
fn a_malformed_root_fails_admission_rather_than_being_skipped() {
    assert_eq!(
        admit_configured_path("/run/ferrum/app.sock", &roots(&["/run/ferrum", "oops"])),
        Err(UnixSocketPathRejection::InvalidContainmentRoot)
    );
}

/// Syntax is checked BEFORE containment, so a traversal segment can never be
/// normalized into an allowed root.
#[test]
fn traversal_is_refused_before_containment_is_consulted() {
    assert_eq!(
        admit_configured_path(
            "/run/ferrum/../../var/run/docker.sock",
            &roots(&["/run/ferrum"])
        ),
        Err(UnixSocketPathRejection::TraversalComponent)
    );
}

// ── Dial-time filesystem gate (the TOCTOU boundary) ──────────────────────────

#[cfg(unix)]
mod connect_time {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Canonicalized so the symlink-resolved containment check agrees with the
    /// configured root (macOS temp dirs live behind `/var` → `/private/var`).
    fn root_dir(temp: &tempfile::TempDir) -> std::path::PathBuf {
        temp.path().canonicalize().expect("canonicalize temp dir")
    }

    fn bind_socket(path: &std::path::Path) -> std::os::unix::net::UnixListener {
        std::os::unix::net::UnixListener::bind(path).expect("bind unix socket")
    }

    /// SAFETY: `geteuid` takes no arguments, reads process state, never fails.
    fn euid() -> u32 {
        unsafe { libc::geteuid() }
    }

    /// The checked identity is the CONTRACT the dial is bound to, so admission
    /// must hand back the canonical path, the real owner, and the real inode —
    /// not merely a yes.
    #[test]
    fn admission_returns_the_checked_identity_of_the_socket() {
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::TempDir::new().expect("temp dir");
        let root = root_dir(&temp);
        let socket = root.join("app.sock");
        let _listener = bind_socket(&socket);
        let admitted = admit_socket_for_connect(
            socket.to_str().expect("utf-8"),
            &roots(&[root.to_str().expect("utf-8")]),
            &[],
        )
        .expect("a contained, self-owned socket is admitted");

        assert_eq!(
            admitted.resolved_path(),
            socket.as_path(),
            "the dial must target the CANONICAL path that was checked, not the configured one"
        );
        assert_eq!(admitted.owner_uid(), euid());
        assert!(
            admitted
                .still_names_checked_object()
                .expect("the socket is still inspectable"),
            "an untouched socket must still match its checked identity"
        );

        // The identity really is inode-pinned: re-binding the same path yields a
        // different object even though the owner and mode are identical.
        let metadata = std::fs::symlink_metadata(&socket).expect("stat socket");
        std::fs::remove_file(&socket).expect("unlink socket");
        let _replacement = bind_socket(&socket);
        let replaced = std::fs::symlink_metadata(&socket).expect("stat replacement");
        assert_ne!(
            (metadata.dev(), metadata.ino()),
            (replaced.dev(), replaced.ino()),
            "re-binding a unix socket must produce a new inode for the identity check to bite"
        );
        assert!(
            !admitted
                .still_names_checked_object()
                .expect("the replacement is inspectable"),
            "a re-bound socket must NOT satisfy the earlier checked identity"
        );
    }

    /// The escape the lexical check cannot see: a symlink INSIDE an allowed root
    /// pointing at a privileged socket outside it. This is precisely the
    /// `/allowed/app.sock -> /var/run/docker.sock` attack.
    #[test]
    fn refuses_a_symlink_that_escapes_the_allowed_root() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let base = root_dir(&temp);
        let allowed = base.join("allowed");
        let elsewhere = base.join("elsewhere");
        std::fs::create_dir_all(&allowed).expect("create allowed dir");
        std::fs::create_dir_all(&elsewhere).expect("create elsewhere dir");
        let privileged = elsewhere.join("privileged.sock");
        let _listener = bind_socket(&privileged);
        let planted = allowed.join("app.sock");
        std::os::unix::fs::symlink(&privileged, &planted).expect("plant symlink");

        // Lexically contained…
        assert_eq!(
            admit_configured_path(
                planted.to_str().expect("utf-8"),
                &roots(&[allowed.to_str().expect("utf-8")]),
            ),
            Ok(())
        );
        // …but the RESOLVED target is not, so the dial-time gate refuses it.
        assert_eq!(
            admit_socket_for_connect(
                planted.to_str().expect("utf-8"),
                &roots(&[allowed.to_str().expect("utf-8")]),
                &[],
            ),
            Err(UnixSocketPathRejection::SymlinkEscape)
        );
    }

    /// A symlink that stays INSIDE an allowed root is fine — containment, not
    /// symlink-phobia, is the rule.
    #[test]
    fn admits_a_symlink_that_stays_inside_the_allowed_root() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let root = root_dir(&temp);
        let real = root.join("real.sock");
        let _listener = bind_socket(&real);
        let link = root.join("link.sock");
        std::os::unix::fs::symlink(&real, &link).expect("plant symlink");
        let admitted = admit_socket_for_connect(
            link.to_str().expect("utf-8"),
            &roots(&[root.to_str().expect("utf-8")]),
            &[],
        )
        .expect("a symlink that stays inside the root is admitted");
        assert_eq!(
            admitted.resolved_path(),
            real.as_path(),
            "the checked identity — and therefore the dial — follows the RESOLVED target"
        );
    }

    #[test]
    fn refuses_a_path_that_is_not_a_socket() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let root = root_dir(&temp);
        let regular = root.join("regular.sock");
        std::fs::write(&regular, b"not a socket").expect("write regular file");
        assert_eq!(
            admit_socket_for_connect(
                regular.to_str().expect("utf-8"),
                &roots(&[root.to_str().expect("utf-8")]),
                &[],
            ),
            Err(UnixSocketPathRejection::NotASocket)
        );

        let directory = root.join("dir.sock");
        std::fs::create_dir(&directory).expect("create dir");
        assert_eq!(
            admit_socket_for_connect(
                directory.to_str().expect("utf-8"),
                &roots(&[root.to_str().expect("utf-8")]),
                &[],
            ),
            Err(UnixSocketPathRejection::NotASocket)
        );
    }

    #[test]
    fn refuses_a_socket_that_does_not_exist() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let root = root_dir(&temp);
        assert_eq!(
            admit_socket_for_connect(
                root.join("absent.sock").to_str().expect("utf-8"),
                &roots(&[root.to_str().expect("utf-8")]),
                &[],
            ),
            Err(UnixSocketPathRejection::UnresolvablePath)
        );
    }

    /// OWNERSHIP: the default admits only the Ferrum process's own effective
    /// uid, so a socket owned by anyone else — the case that matters for a
    /// root-owned system socket sitting in an allowed directory — is refused.
    /// The test asserts it by allow-listing a uid the socket cannot have.
    #[test]
    fn refuses_a_socket_whose_owner_is_not_admitted() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let root = root_dir(&temp);
        let socket = root.join("app.sock");
        let _listener = bind_socket(&socket);
        let euid = euid();
        let other_uid = euid.wrapping_add(1);
        assert_eq!(
            admit_socket_for_connect(
                socket.to_str().expect("utf-8"),
                &roots(&[root.to_str().expect("utf-8")]),
                &[other_uid],
            ),
            Err(UnixSocketPathRejection::UnexpectedOwner),
            "an owner uid outside the allowlist must be refused"
        );
        // The same socket IS admitted once its real owner is allow-listed,
        // proving the refusal was the ownership rule and nothing else.
        let admitted = admit_socket_for_connect(
            socket.to_str().expect("utf-8"),
            &roots(&[root.to_str().expect("utf-8")]),
            &[other_uid, euid],
        )
        .expect("the socket's real owner is allow-listed");
        assert_eq!(
            admitted.owner_uid(),
            euid,
            "the checked identity pins the socket's ACTUAL owner, not the allowlist — the \
             connected peer is compared against this exact uid"
        );
    }

    /// MODE: a world-writable socket lets any local user connect to — or, with
    /// directory write access, replace — the application endpoint.
    #[test]
    fn refuses_a_world_writable_socket() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let root = root_dir(&temp);
        let socket = root.join("app.sock");
        let _listener = bind_socket(&socket);
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o777))
            .expect("chmod socket world-writable");
        assert_eq!(
            admit_socket_for_connect(
                socket.to_str().expect("utf-8"),
                &roots(&[root.to_str().expect("utf-8")]),
                &[],
            ),
            Err(UnixSocketPathRejection::WorldWritableSocket)
        );
    }

    /// MODE (parent): a world-writable directory WITHOUT the sticky bit is the
    /// precondition for winning the connect-time race — any local user can
    /// unlink the socket and bind their own in its place — so it is refused
    /// rather than merely narrowed. The sticky-bit form (`/tmp` semantics) is
    /// allowed, but ONLY because the same walk requires every directory owner
    /// and the socket owner to be trusted; see
    /// [`sticky_never_rescues_an_untrusted_directory_owner_or_entry`].
    #[test]
    fn refuses_a_socket_in_a_world_writable_non_sticky_directory() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let base = root_dir(&temp);
        let dir = base.join("open");
        std::fs::create_dir(&dir).expect("create dir");
        let socket = dir.join("app.sock");
        let _listener = bind_socket(&socket);
        let allowed = roots(&[base.to_str().expect("utf-8")]);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))
            .expect("chmod dir world-writable");
        assert_eq!(
            admit_socket_for_connect(socket.to_str().expect("utf-8"), &allowed, &[]),
            Err(UnixSocketPathRejection::UnsafeDirectoryPermissions)
        );

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777))
            .expect("chmod dir sticky");
        assert!(
            admit_socket_for_connect(socket.to_str().expect("utf-8"), &allowed, &[]).is_ok(),
            "sticky + trusted owners is the one admissible world-writable form"
        );
    }

    /// GROUP-writable matters as much as world-writable: the group of a shared
    /// socket directory is exactly the boundary a co-tenant crosses, and a
    /// group member can rename the socket away and bind their own.
    #[test]
    fn refuses_a_socket_in_a_group_writable_non_sticky_directory() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let base = root_dir(&temp);
        let dir = base.join("shared");
        std::fs::create_dir(&dir).expect("create dir");
        let socket = dir.join("app.sock");
        let _listener = bind_socket(&socket);
        let allowed = roots(&[base.to_str().expect("utf-8")]);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775))
            .expect("chmod dir group-writable");
        assert_eq!(
            admit_socket_for_connect(socket.to_str().expect("utf-8"), &allowed, &[]),
            Err(UnixSocketPathRejection::UnsafeDirectoryPermissions),
            "a group-writable parent is a rename primitive for every group member"
        );

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("chmod dir back");
        assert!(admit_socket_for_connect(socket.to_str().expect("utf-8"), &allowed, &[]).is_ok());
    }

    /// A group- or world-writable SOCKET is refused too: an outsider who can
    /// write the socket file can also connect to it as a peer.
    #[test]
    fn refuses_a_group_writable_socket() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let root = root_dir(&temp);
        let socket = root.join("app.sock");
        let _listener = bind_socket(&socket);
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o775))
            .expect("chmod socket group-writable");
        assert_eq!(
            admit_socket_for_connect(
                socket.to_str().expect("utf-8"),
                &roots(&[root.to_str().expect("utf-8")]),
                &[],
            ),
            Err(UnixSocketPathRejection::WorldWritableSocket)
        );
    }

    /// THE ANCESTOR HOLE: checking only the socket's immediate parent lets an
    /// attacker who controls a directory HIGHER in the chain rename the entire
    /// checked subtree and substitute it wholesale — the inspected parent
    /// itself is never modified, so a parent-only check sees nothing wrong.
    /// Every directory up to the containment root must therefore be checked.
    #[test]
    fn refuses_a_writable_ancestor_above_a_pristine_parent() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let base = root_dir(&temp);
        let ancestor = base.join("ancestor");
        let parent = ancestor.join("parent");
        std::fs::create_dir_all(&parent).expect("create chain");
        let socket = parent.join("app.sock");
        let _listener = bind_socket(&socket);
        let allowed = roots(&[base.to_str().expect("utf-8")]);

        // The immediate parent is impeccable throughout this test.
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("chmod parent");

        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o777))
            .expect("chmod ancestor world-writable");
        assert_eq!(
            admit_socket_for_connect(socket.to_str().expect("utf-8"), &allowed, &[]),
            Err(UnixSocketPathRejection::UnsafeDirectoryPermissions),
            "a writable ancestor can rename the whole checked subtree, so it must be refused \
             even when the immediate parent is safe"
        );

        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o755))
            .expect("chmod ancestor back");
        assert!(admit_socket_for_connect(socket.to_str().expect("utf-8"), &allowed, &[]).is_ok());
    }

    /// The containment ROOT is inside the walk, not above it: it is the
    /// operator's declared trust boundary and must itself be non-writable.
    #[test]
    fn the_containment_root_itself_is_part_of_the_checked_chain() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let base = root_dir(&temp);
        let socket = base.join("app.sock");
        let _listener = bind_socket(&socket);
        let allowed = roots(&[base.to_str().expect("utf-8")]);

        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777))
            .expect("chmod root world-writable");
        assert_eq!(
            admit_socket_for_connect(socket.to_str().expect("utf-8"), &allowed, &[]),
            Err(UnixSocketPathRejection::UnsafeDirectoryPermissions)
        );
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755))
            .expect("chmod root back");
    }

    /// The dial-time gate re-runs the FULL configured-path gate, so the
    /// default-off posture holds at the TOCTOU boundary too.
    #[test]
    fn the_connect_time_gate_still_refuses_an_unconfigured_allowlist() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let root = root_dir(&temp);
        let socket = root.join("app.sock");
        let _listener = bind_socket(&socket);
        assert_eq!(
            admit_socket_for_connect(socket.to_str().expect("utf-8"), &[], &[]),
            Err(UnixSocketPathRejection::ContainmentNotConfigured)
        );
    }
}

// ── Directory-chain policy (the mutation-path rules, as a pure function) ─────
//
// The ownership half of the policy cannot be exercised against a real
// filesystem without root — an unprivileged test cannot create a directory
// owned by someone else — so the policy is a pure function of the directory's
// facts and is pinned here against exactly the combinations an attacker would
// arrange. The real walk feeds it `symlink_metadata`, so these are the rules
// the dial actually enforces, not a restatement of them.

#[cfg(unix)]
mod directory_chain_policy {
    use ferrum_edge::util::unix_socket::{
        DirectoryFacts, UnixSocketPathRejection, admit_directory_facts,
    };

    /// The trust boundary the walk is given: uid 0 (root can rewrite any of these
    /// checks anyway), this process, and the configured application uid.
    const TRUSTED: &[u32] = &[0, 1000, 1001];
    /// A uid outside that boundary — an ordinary local user or a co-tenant.
    const HOSTILE_UID: u32 = 4242;

    fn dir_facts(uid: u32, mode: u32) -> DirectoryFacts {
        DirectoryFacts {
            uid,
            mode,
            is_dir: true,
            is_symlink: false,
        }
    }

    #[test]
    fn an_ordinary_trusted_directory_is_admitted() {
        for mode in [0o755, 0o750, 0o700, 0o555] {
            assert_eq!(
                admit_directory_facts(&dir_facts(1000, mode), TRUSTED),
                Ok(()),
                "mode {mode:o} owned by a trusted uid must be admitted"
            );
        }
    }

    /// A directory owned outside the trust boundary is refused whatever its mode:
    /// its owner can rename or replace every descendant, and can `chmod` away any
    /// protective bit — including sticky — at will.
    #[test]
    fn an_untrusted_directory_owner_is_refused_at_every_mode() {
        for mode in [0o755, 0o700, 0o1777, 0o500, 0o000] {
            assert_eq!(
                admit_directory_facts(&dir_facts(HOSTILE_UID, mode), TRUSTED),
                Err(UnixSocketPathRejection::UntrustedDirectoryOwner),
                "mode {mode:o} must not rescue a directory owned by an untrusted uid"
            );
        }
    }

    /// THE STICKY-BIT EXCEPTION, stated exactly. Sticky only stops a user from
    /// renaming or unlinking an entry they do NOT own; the directory's own owner is
    /// always exempt, and so is the entry's owner. So sticky is admissible only in
    /// combination with the trusted-owner rule (checked here) and the socket-owner
    /// rule (checked by `refuses_a_socket_whose_owner_is_not_admitted`).
    #[test]
    fn sticky_never_rescues_an_untrusted_directory_owner_or_entry() {
        // Sticky + trusted owner: admissible — no untrusted group member can rename
        // an entry owned by a trusted uid.
        assert_eq!(
            admit_directory_facts(&dir_facts(1000, 0o1777), TRUSTED),
            Ok(())
        );
        // Sticky + UNTRUSTED owner: the directory owner is exempt from sticky, so
        // the bit proves nothing and the directory is refused.
        assert_eq!(
            admit_directory_facts(&dir_facts(HOSTILE_UID, 0o1777), TRUSTED),
            Err(UnixSocketPathRejection::UntrustedDirectoryOwner)
        );
    }

    /// Without sticky, any group or world write permission is a rename primitive
    /// for someone outside the trust boundary. Group membership is not knowable
    /// from the metadata, so this fails closed rather than guessing.
    #[test]
    fn group_or_world_writable_without_sticky_is_refused() {
        for mode in [0o775, 0o707, 0o777, 0o770, 0o722] {
            assert_eq!(
                admit_directory_facts(&dir_facts(1000, mode), TRUSTED),
                Err(UnixSocketPathRejection::UnsafeDirectoryPermissions),
                "mode {mode:o} lets a non-owner rename the checked descendant"
            );
        }
    }

    /// A symlink or a non-directory on the chain moves (or hides) the whole subtree
    /// somewhere the containment check never inspected, so it is refused before
    /// ownership or permissions are even consulted.
    #[test]
    fn a_symlinked_or_non_directory_chain_component_is_refused() {
        assert_eq!(
            admit_directory_facts(
                &DirectoryFacts {
                    uid: 1000,
                    mode: 0o755,
                    is_dir: true,
                    is_symlink: true,
                },
                TRUSTED
            ),
            Err(UnixSocketPathRejection::UnsafeDirectoryComponent)
        );
        assert_eq!(
            admit_directory_facts(
                &DirectoryFacts {
                    uid: 1000,
                    mode: 0o644,
                    is_dir: false,
                    is_symlink: false,
                },
                TRUSTED
            ),
            Err(UnixSocketPathRejection::UnsafeDirectoryComponent)
        );
    }
}
