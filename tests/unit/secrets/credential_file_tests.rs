//! Issue #3759: shared bounded credential-file reader.
//!
//! Covers empty/ordinary/newline/invalid UTF-8, exact limit and limit+1,
//! concurrent growth past metadata, sparse oversized files, non-regular
//! rejection before blocking, projected-secret symlink rotation, Tokio
//! heartbeat non-stall, and source/value redaction.

use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferrum_edge::_test_support::write_sparse_credential_fixture_for_test;
use ferrum_edge::secrets::credential_file::{
    CredentialFileError, CredentialTrim, DEFAULT_CREDENTIAL_FILE_MAX_BYTES,
    HARD_MAX_CREDENTIAL_FILE_MAX_BYTES, read_bounded_credential_bytes, read_credential_file,
    read_credential_file_detached, validate_credential_file_max_bytes,
};
use ferrum_edge::secrets::file::{read_secret, read_secret_detached};

const LIMIT: usize = 64;

fn assert_no_leak(rendered: &str, forbidden: &[&str]) {
    for fragment in forbidden {
        assert!(
            !rendered.contains(fragment),
            "credential diagnostic leaked '{fragment}': {rendered}"
        );
    }
}

#[test]
fn ordinary_content_and_trailing_newline_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, b"credential-value\n").unwrap();
    let got = read_credential_file(
        path.to_str().unwrap(),
        LIMIT,
        CredentialTrim::TrailingWhitespace,
    )
    .expect("ordinary");
    assert_eq!(got, "credential-value");
}

#[test]
fn empty_and_whitespace_only_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty");
    std::fs::write(&empty, b"").unwrap();
    assert!(matches!(
        read_credential_file(empty.to_str().unwrap(), LIMIT, CredentialTrim::Ends),
        Err(CredentialFileError::Empty)
    ));

    let blank = dir.path().join("blank");
    std::fs::write(&blank, b" \n\t").unwrap();
    assert!(matches!(
        read_credential_file(blank.to_str().unwrap(), LIMIT, CredentialTrim::Ends),
        Err(CredentialFileError::Empty)
    ));
}

#[test]
fn invalid_utf8_is_rejected_without_echoing_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad-utf8");
    std::fs::write(&path, [0xff, 0xfe, 0xfd]).unwrap();
    let error = read_credential_file(path.to_str().unwrap(), LIMIT, CredentialTrim::Ends)
        .expect_err("invalid utf8");
    assert!(matches!(error, CredentialFileError::InvalidUtf8));
    let rendered = error.to_string();
    assert_no_leak(&rendered, &["\u{fffd}", path.to_str().unwrap()]);
    assert!(!rendered.as_bytes().contains(&0xff));
}

#[test]
fn exact_limit_loads_and_limit_plus_one_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let exact = dir.path().join("exact");
    std::fs::write(&exact, vec![b'a'; LIMIT]).unwrap();
    let got = read_credential_file(
        exact.to_str().unwrap(),
        LIMIT,
        CredentialTrim::TrailingWhitespace,
    )
    .expect("exact");
    assert_eq!(got.len(), LIMIT);

    let over = dir.path().join("over");
    std::fs::write(&over, vec![b'b'; LIMIT + 1]).unwrap();
    let error = read_credential_file(
        over.to_str().unwrap(),
        LIMIT,
        CredentialTrim::TrailingWhitespace,
    )
    .expect_err("limit+1");
    match error {
        CredentialFileError::Oversized { max_bytes } => assert_eq!(max_bytes, LIMIT),
        other => panic!("expected Oversized, got {other}"),
    }
    assert_no_leak(
        &error.to_string(),
        &[over.to_str().unwrap(), &"b".repeat(LIMIT + 1)],
    );
}

#[test]
fn bounded_reader_seam_rejects_after_metadata_precheck_would_have_passed() {
    let error = read_bounded_credential_bytes(Cursor::new(vec![b'g'; LIMIT + 1]), LIMIT)
        .expect_err("limit+1");
    match error {
        CredentialFileError::Oversized { max_bytes } => assert_eq!(max_bytes, LIMIT),
        other => panic!("expected Oversized, got {other}"),
    }
    let ok = read_bounded_credential_bytes(Cursor::new(vec![b'g'; LIMIT]), LIMIT).expect("exact");
    assert_eq!(ok.len(), LIMIT);
}

#[test]
fn concurrent_growth_is_capped_by_streaming_budget() {
    // Race-free proof: a reader that already passed a "metadata says small"
    // check still terminates at limit+1 when the stream grows.
    struct GrowingThenOversize {
        served: usize,
    }
    impl std::io::Read for GrowingThenOversize {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.served > LIMIT {
                return Ok(0);
            }
            let n = buf
                .len()
                .min(LIMIT.saturating_add(1).saturating_sub(self.served));
            for slot in &mut buf[..n] {
                *slot = b'x';
            }
            self.served += n;
            Ok(n)
        }
    }

    let error = read_bounded_credential_bytes(GrowingThenOversize { served: 0 }, LIMIT)
        .expect_err("grown past ceiling");
    assert!(matches!(
        error,
        CredentialFileError::Oversized { max_bytes: LIMIT }
    ));
}

#[test]
fn sparse_large_file_is_rejected_without_full_allocation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sparse");
    write_sparse_credential_fixture_for_test(&path, b"tok", (LIMIT as u64) + 1).expect("sparse");
    let before = {
        #[cfg(target_os = "linux")]
        {
            // Best-effort: logical size is what we gate on; physical blocks may
            // still be sparse depending on the filesystem.
            path.metadata().unwrap().len()
        }
        #[cfg(not(target_os = "linux"))]
        {
            path.metadata().unwrap().len()
        }
    };
    assert!(before > LIMIT as u64);
    let error = read_credential_file(path.to_str().unwrap(), LIMIT, CredentialTrim::Ends)
        .expect_err("sparse");
    assert!(matches!(
        error,
        CredentialFileError::Oversized { max_bytes: LIMIT }
    ));
}

#[cfg(unix)]
#[test]
fn fifo_is_rejected_before_blocking_read() {
    use std::os::unix::ffi::OsStrExt as _;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cred.fifo");
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: live NUL-terminated path; ordinary mode bits.
    assert_eq!(unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) }, 0);

    let started = std::time::Instant::now();
    let error = read_credential_file(path.to_str().unwrap(), LIMIT, CredentialTrim::Ends)
        .expect_err("fifo");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "FIFO rejection must not wait for a writer"
    );
    assert!(matches!(error, CredentialFileError::NotRegularFile));
    assert_no_leak(&error.to_string(), &[path.to_str().unwrap()]);
}

#[cfg(unix)]
#[test]
fn unix_socket_is_rejected_before_blocking_read() {
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cred.sock");
    let _listener = UnixListener::bind(&path).unwrap();
    let started = std::time::Instant::now();
    let error = read_credential_file(path.to_str().unwrap(), LIMIT, CredentialTrim::Ends)
        .expect_err("socket");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(matches!(error, CredentialFileError::NotRegularFile));
}

#[cfg(unix)]
#[test]
fn character_device_is_rejected_without_reading() {
    // /dev/null is a character device; reading it would succeed with empty
    // content, but the type gate must refuse before any credential decode.
    let error = read_credential_file("/dev/null", LIMIT, CredentialTrim::Ends).expect_err("device");
    assert!(matches!(error, CredentialFileError::NotRegularFile));
    assert_no_leak(&error.to_string(), &["/dev/null"]);
}

#[test]
fn directory_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let error = read_credential_file(dir.path().to_str().unwrap(), LIMIT, CredentialTrim::Ends)
        .expect_err("directory");
    assert!(matches!(
        error,
        CredentialFileError::NotRegularFile | CredentialFileError::Io(_)
    ));
    assert_no_leak(&error.to_string(), &[dir.path().to_str().unwrap()]);
}

#[cfg(unix)]
#[test]
fn projected_secret_symlink_and_atomic_target_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let data_v1 = dir.path().join("..data_v1");
    let data_v2 = dir.path().join("..data_v2");
    std::fs::create_dir(&data_v1).unwrap();
    std::fs::create_dir(&data_v2).unwrap();
    std::fs::write(data_v1.join("token"), b"token-v1\n").unwrap();
    std::fs::write(data_v2.join("token"), b"token-v2\n").unwrap();

    let data_link = dir.path().join("..data");
    std::os::unix::fs::symlink(&data_v1, &data_link).unwrap();
    let token_link = dir.path().join("token");
    std::os::unix::fs::symlink("..data/token", &token_link).unwrap();

    let first = read_credential_file(
        token_link.to_str().unwrap(),
        LIMIT,
        CredentialTrim::TrailingWhitespace,
    )
    .expect("v1");
    assert_eq!(first, "token-v1");

    // Atomic projected-secret rotation: replace the `..data` symlink.
    let tmp_link = dir.path().join("..data_tmp");
    std::os::unix::fs::symlink(&data_v2, &tmp_link).unwrap();
    std::fs::rename(&tmp_link, &data_link).unwrap();

    let second = read_credential_file(
        token_link.to_str().unwrap(),
        LIMIT,
        CredentialTrim::TrailingWhitespace,
    )
    .expect("v2");
    assert_eq!(second, "token-v2");
}

#[test]
fn missing_path_errors_are_source_redacted() {
    let missing = "/nonexistent/ferrum-credential-source-sentinel";
    let error = read_credential_file(missing, LIMIT, CredentialTrim::Ends).expect_err("missing");
    assert!(
        matches!(error, CredentialFileError::PathNotFound),
        "genuine pathname absence must be PathNotFound, got: {error:?}"
    );
    assert_eq!(error.to_string(), "credential path not found");
    assert_no_leak(
        &error.to_string(),
        &["ferrum-credential-source-sentinel", missing],
    );
}

#[cfg(unix)]
#[test]
fn broken_projected_symlink_is_open_time_not_found_not_path_absent() {
    let dir = tempfile::tempdir().unwrap();
    let missing_target = dir.path().join("missing-projected-target-sentinel");
    let link = dir.path().join("broken-projected-token-link-sentinel");
    std::os::unix::fs::symlink(&missing_target, &link).unwrap();

    let error = read_credential_file(link.to_str().unwrap(), LIMIT, CredentialTrim::Ends)
        .expect_err("broken projected symlink");
    assert!(
        !matches!(error, CredentialFileError::PathNotFound),
        "an existing symlink pathname must not map to PathNotFound"
    );
    assert!(
        matches!(
            error,
            CredentialFileError::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound
        ),
        "broken target must surface as open-time Io(NotFound), got: {error:?}"
    );
    assert_no_leak(
        &error.to_string(),
        &[
            "broken-projected-token-link-sentinel",
            "missing-projected-target-sentinel",
            link.to_str().unwrap(),
        ],
    );
}

#[test]
fn limit_validation_rejects_zero_and_above_hard_max() {
    assert!(matches!(
        validate_credential_file_max_bytes(0),
        Err(CredentialFileError::InvalidLimit { max_bytes: 0 })
    ));
    assert!(matches!(
        validate_credential_file_max_bytes(HARD_MAX_CREDENTIAL_FILE_MAX_BYTES + 1),
        Err(CredentialFileError::InvalidLimit { .. })
    ));
    assert_eq!(
        validate_credential_file_max_bytes(DEFAULT_CREDENTIAL_FILE_MAX_BYTES).unwrap(),
        DEFAULT_CREDENTIAL_FILE_MAX_BYTES
    );
}

#[test]
fn file_secret_backend_routes_through_shared_reader() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret");
    std::fs::write(&path, b"shared-secret\n").unwrap();
    assert_eq!(
        read_secret(path.to_str().unwrap(), "TEST_KEY").unwrap(),
        "shared-secret"
    );

    let over = dir.path().join("over");
    std::fs::write(&over, vec![b'x'; DEFAULT_CREDENTIAL_FILE_MAX_BYTES + 1]).unwrap();
    let error = read_secret(over.to_str().unwrap(), "TEST_KEY").expect_err("oversize");
    assert!(error.contains("TEST_KEY_FILE"));
    assert!(error.contains("exceeds the maximum"));
    assert_no_leak(&error, &[over.to_str().unwrap(), &"x".repeat(32)]);
}

#[test]
fn detached_file_secret_rejects_non_regular_without_stall() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let error = rt
        .block_on(read_secret_detached(
            dir.path().to_str().unwrap(),
            "DIR_KEY",
        ))
        .expect_err("directory");
    assert!(error.contains("DIR_KEY_FILE"));
    assert_no_leak(&error, &[dir.path().to_str().unwrap()]);
}

#[test]
fn tokio_heartbeat_continues_while_credential_read_runs_off_worker() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ok-token");
    std::fs::write(&path, b"heartbeat-token\n").unwrap();
    let path = path.to_str().unwrap().to_string();

    let beats = Arc::new(AtomicBool::new(false));
    let beats_flag = beats.clone();

    rt.block_on(async move {
        let heartbeat = tokio::spawn(async move {
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(5)).await;
                beats_flag.store(true, Ordering::Release);
            }
        });

        let token = read_credential_file_detached(
            &path,
            LIMIT,
            CredentialTrim::TrailingWhitespace,
            "ferrum-cred-test",
        )
        .await
        .expect("detached read");
        assert_eq!(token, "heartbeat-token");

        // Give the heartbeat a moment if the read was extremely fast.
        tokio::time::sleep(Duration::from_millis(30)).await;
        heartbeat.await.unwrap();
        assert!(
            beats.load(Ordering::Acquire),
            "Tokio heartbeat must keep running while credential I/O is off-worker"
        );
    });
}

#[cfg(unix)]
#[test]
fn fifo_rejection_does_not_leave_a_blocked_detached_reader() {
    use std::os::unix::ffi::OsStrExt as _;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("detach.fifo");
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) }, 0);
    let path_s = path.to_str().unwrap().to_string();

    let error = rt.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(2),
            read_credential_file_detached(
                &path_s,
                LIMIT,
                CredentialTrim::Ends,
                "ferrum-cred-fifo-test",
            ),
        )
        .await
        .expect("FIFO type rejection must finish before timeout")
        .expect_err("FIFO")
    });
    assert!(matches!(error, CredentialFileError::NotRegularFile));
}

#[test]
fn detached_bounded_reader_timeout_does_not_pin_runtime_teardown() {
    use std::io::Read;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const WATCHDOG: Duration = Duration::from_secs(30);
    const FETCH_TIMEOUT: Duration = Duration::from_millis(50);
    const EXPECTED_CEILING: Duration = Duration::from_secs(2);

    struct StallRead {
        gate: Arc<AtomicBool>,
    }

    impl Read for StallRead {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            while !self.gate.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(0)
        }
    }

    let gate = Arc::new(AtomicBool::new(false));
    let gate_worker = gate.clone();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let started = Instant::now();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let join_handle = std::thread::spawn(move || {
                let _ = tx.send(read_bounded_credential_bytes(
                    StallRead { gate: gate_worker },
                    LIMIT,
                ));
            });
            drop(join_handle);
            tokio::time::timeout(FETCH_TIMEOUT, rx).await
        });
        let _ = sender.send((result, started.elapsed()));
    });

    let (result, elapsed) = receiver
        .recv_timeout(WATCHDOG)
        .expect("detached bounded-reader timeout and runtime teardown must complete");
    assert!(
        result.is_err(),
        "stalling reader must exceed the fetch timeout, got: {result:?}"
    );
    assert!(
        elapsed < EXPECTED_CEILING,
        "timeout path must finish promptly, took {elapsed:?}"
    );
    gate.store(true, Ordering::Release);
}

#[test]
fn shared_reader_source_text_is_the_single_production_seam() {
    let file_src = include_str!("../../../src/secrets/file.rs");
    let cred_src = include_str!("../../../src/secrets/credential_file.rs");
    let dp_src = include_str!("../../../src/grpc/dp_client.rs");

    assert!(cred_src.contains("read_credential_file"));
    assert!(cred_src.contains("O_NONBLOCK") || cfg!(not(unix)));
    assert!(file_src.contains("credential_file::read_credential_file"));
    assert!(file_src.contains("read_credential_file_detached"));
    assert!(dp_src.contains("read_credential_file"));
    assert!(dp_src.contains("mint_async"));
    let k8s_src = include_str!("../../../src/service_discovery/kubernetes.rs");
    assert!(k8s_src.contains("read_credential_file_detached_guarded"));
    assert!(
        !dp_src
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .any(|line| line.contains("read_to_string(path)")),
        "DP token path must not call unbounded read_to_string"
    );
    assert!(
        !k8s_src
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .any(|line| line.contains("read_to_string(")),
        "Kubernetes SA token path must not call unbounded read_to_string"
    );
}
