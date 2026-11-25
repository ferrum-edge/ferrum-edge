//! Windows-only tenant TLS file confinement tests.
//!
//! Kept in a dedicated integration-test target so `.github/workflows/windows-confinement.yml`
//! compiles and runs only these Windows kernel confinement assertions on
//! `windows-latest` instead of compiling the full multi-thousand-test `unit_tests`
//! target (issue #6540).

#![cfg(windows)]

mod windows_confined_files {
    use ferrum_edge::_test_support::{
        bind_tenant_tls_file_for_test, load_tenant_tls_file_for_test as load,
        open_resolved_tenant_tls_file_for_test as open,
    };
    use ferrum_edge::tls::source::{MaterialKind, check_namespace_scoped_material_reference};
    use std::io::Read;
    use std::path::PathBuf;

    const INLINE_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    fn check(value: &str, kind: MaterialKind, roots: &[PathBuf]) -> Result<(), String> {
        check_namespace_scoped_material_reference(value, kind, "tenant-a", roots)
            .map_err(|refusal| format!("{refusal:?}"))
    }

    fn bound_file(value: &str, kind: MaterialKind) -> String {
        bind_tenant_tls_file_for_test(value, kind).unwrap().unwrap()
    }

    // Real mount-point reparse fixtures do not require symlink privilege. Keep
    // the documented kernel operation in test code; no shell/mklink process.
    fn junction_buffer(target: &std::path::Path) -> Vec<u8> {
        use std::os::windows::ffi::OsStrExt;
        let target = std::fs::canonicalize(target).unwrap();
        let target = target.to_str().unwrap().strip_prefix(r"\\?\").unwrap();
        assert!(target.as_bytes().get(1) == Some(&b':'), "local DOS fixture");
        let substitute: Vec<u16> = std::ffi::OsStr::new(&format!(r"\??\{target}"))
            .encode_wide()
            .collect();
        let print: Vec<u16> = std::ffi::OsStr::new(target).encode_wide().collect();
        let sub_len = u16::try_from(substitute.len() * 2).unwrap();
        let print_len = u16::try_from(print.len() * 2).unwrap();
        let data_len =
            u16::try_from(8 + usize::from(sub_len) + usize::from(print_len) + 4).unwrap();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&0xa000_0003u32.to_le_bytes()); // IO_REPARSE_TAG_MOUNT_POINT
        for word in [data_len, 0, 0, sub_len, sub_len + 2, print_len] {
            buffer.extend_from_slice(&word.to_le_bytes());
        }
        for word in substitute.into_iter().chain([0]).chain(print).chain([0]) {
            buffer.extend_from_slice(&word.to_le_bytes());
        }
        buffer
    }

    fn reparse_control(file: &std::fs::File, control: u32, buffer: &[u8]) -> std::io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn DeviceIoControl(
                device: *mut std::ffi::c_void,
                control: u32,
                input: *const std::ffi::c_void,
                input_size: u32,
                output: *mut std::ffi::c_void,
                output_size: u32,
                bytes_returned: *mut u32,
                overlapped: *mut std::ffi::c_void,
            ) -> i32;
        }
        let mut returned = 0;
        // SAFETY: live owned directory handle and valid counted reparse buffer;
        // synchronous call, no output/overlapped storage.
        let success = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                control,
                buffer.as_ptr().cast(),
                u32::try_from(buffer.len()).unwrap(),
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if success == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn junction(target: &std::path::Path, link: &std::path::Path) {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::create_dir(link).unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(link)
            .unwrap();
        reparse_control(&file, 0x0009_00a4, &junction_buffer(target))
            .expect("junction fixture must support FSCTL_SET_REPARSE_POINT");
    }

    #[test]
    fn windows_plain_and_file_uri_loads_keep_unicode_paths_and_rotation() {
        let temp = tempfile::tempdir().unwrap();
        // Hosted runners report TEMP through an 8.3 short name
        // (`C:\Users\RUNNER~1\...`), which the lexical root check cannot
        // equate with the long canonical form below. Configure the root in
        // its long DOS form, as an operator would.
        let long_root = std::fs::canonicalize(temp.path()).unwrap();
        let long_root = PathBuf::from(long_root.to_str().unwrap().strip_prefix(r"\\?\").unwrap());
        let root_paths = [long_root.clone()];
        let file = long_root.join("certificate α&+%.pem");
        std::fs::write(&file, INLINE_CERT).unwrap();
        for value in [
            file.display().to_string(),
            format!("file://{}", file.display()),
            std::fs::canonicalize(&file).unwrap().display().to_string(),
            file.display().to_string().to_ascii_lowercase(),
        ] {
            let bound = bound_file(&value, MaterialKind::Cert);
            assert_eq!(
                load(&bound, MaterialKind::Cert, &root_paths, 1024)
                    .unwrap_or_else(|error| panic!("{value}: {error:?}"))
                    .bytes
                    .expose_secret(),
                INLINE_CERT.as_bytes()
            );
            let replacement = long_root.join("replacement.pem");
            std::fs::write(&replacement, b"rotated in-root bytes").unwrap();
            std::fs::rename(&replacement, &file).unwrap();
            assert_eq!(
                load(&bound, MaterialKind::Cert, &root_paths, 1024)
                    .unwrap()
                    .bytes
                    .expose_secret(),
                b"rotated in-root bytes"
            );
            std::fs::write(&file, INLINE_CERT).unwrap();
        }
    }

    #[test]
    fn windows_admission_accepts_dos_verbatim_and_case_but_preserves_root_boundaries() {
        let root = PathBuf::from(r"C:\Tenant\Certificates");
        for path in [
            r"c:\tenant\certificates\a.pem",
            r"\\?\C:\Tenant\Certificates\a.pem",
        ] {
            assert_eq!(
                check(path, MaterialKind::Cert, std::slice::from_ref(&root)),
                Ok(())
            );
        }
        for path in [
            r"D:\Tenant\Certificates\a.pem",
            r"C:\Tenant\Certificates-other\a.pem",
            r"C:\Tenant\Certificates\..\outside.pem",
            r"\\.\C:\Tenant\Certificates\a.pem",
        ] {
            assert!(check(path, MaterialKind::Cert, std::slice::from_ref(&root)).is_err());
        }
        let unc = PathBuf::from(r"\\server\certs\Tenant");
        assert_eq!(
            check(
                r"\\?\UNC\SERVER\CERTS\tenant\a.pem",
                MaterialKind::Cert,
                std::slice::from_ref(&unc)
            ),
            Ok(())
        );
        for path in [
            r"\\other\certs\Tenant\a.pem",
            r"\\server\other\Tenant\a.pem",
        ] {
            assert!(check(path, MaterialKind::Cert, std::slice::from_ref(&unc)).is_err());
        }
    }

    #[test]
    fn windows_stable_in_root_junction_and_operator_root_alias_are_supported() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let data = root.path().join("generation");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("cert.pem"), INLINE_CERT).unwrap();
        let alias = outside.path().join("operator-root");
        junction(root.path(), &alias);
        let projection = root.path().join("current");
        junction(&data, &projection);
        let file = alias.join("current").join("cert.pem");
        let bound = bound_file(file.to_str().unwrap(), MaterialKind::Cert);
        assert_eq!(
            load(
                &bound,
                MaterialKind::Cert,
                std::slice::from_ref(&alias),
                1024
            )
            .unwrap()
            .bytes
            .expose_secret(),
            INLINE_CERT.as_bytes()
        );
        std::fs::write(data.join("cert.pem"), b"next generation").unwrap();
        assert_eq!(
            load(
                &bound,
                MaterialKind::Cert,
                std::slice::from_ref(&alias),
                1024
            )
            .unwrap()
            .bytes
            .expose_secret(),
            b"next generation"
        );
        std::fs::remove_dir(&projection).unwrap();
        std::fs::write(outside.path().join("cert.pem"), b"outside private bytes").unwrap();
        junction(outside.path(), &projection);
        assert!(
            load(
                &bound,
                MaterialKind::Cert,
                std::slice::from_ref(&alias),
                1024
            )
            .is_err()
        );
        let trusted = ferrum_edge::tls::source::CertSource::from_path(&file);
        assert_eq!(
            ferrum_edge::tls::source::load_material_blocking_with(
                &trusted,
                MaterialKind::Cert,
                1024
            )
            .unwrap()
            .bytes
            .expose_secret(),
            b"outside private bytes"
        );
        std::fs::remove_dir(&projection).unwrap();
        std::fs::remove_dir(&alias).unwrap();
    }

    #[test]
    fn windows_final_symlink_replacement_after_resolution_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let file = root.path().join("cert.pem");
        let target = outside.path().join("private.pem");
        std::fs::write(&file, INLINE_CERT).unwrap();
        std::fs::write(&target, b"outside private bytes").unwrap();
        let checked = std::fs::canonicalize(&file).unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        std::fs::remove_file(&file).unwrap();
        std::os::windows::fs::symlink_file(&target, &file)
            .expect("Windows security gate requires symlink privilege or Developer Mode");
        assert!(open(&canonical_root, &checked).is_err());
        std::fs::remove_file(&file).unwrap(); // failed open must release every handle
    }

    #[test]
    fn windows_ancestor_junction_replacement_after_resolution_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let nested = root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let file = nested.join("cert.pem");
        std::fs::write(&file, INLINE_CERT).unwrap();
        std::fs::write(outside.path().join("cert.pem"), b"outside private bytes").unwrap();
        let checked = std::fs::canonicalize(&file).unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        std::fs::remove_file(&file).unwrap();
        std::fs::remove_dir(&nested).unwrap();
        junction(outside.path(), &nested);
        assert!(open(&canonical_root, &checked).is_err());
        std::fs::remove_dir(&nested).unwrap();
    }

    #[test]
    fn windows_verified_handle_cannot_be_rewritten_or_replaced_before_read() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("cert.pem");
        let replacement = root.path().join("replacement.pem");
        std::fs::write(&file, INLINE_CERT).unwrap();
        std::fs::write(&replacement, b"rotated in-root bytes").unwrap();
        let checked = std::fs::canonicalize(&file).unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        let mut handle = open(&canonical_root, &checked).unwrap();
        assert!(std::fs::write(&file, b"in-place replacement").is_err());
        assert!(std::fs::rename(&replacement, &file).is_err());
        let mut bytes = Vec::new();
        handle.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, INLINE_CERT.as_bytes());
        drop(handle);
        std::fs::rename(&replacement, &file).unwrap();
        let bound = bound_file(file.to_str().unwrap(), MaterialKind::Cert);
        assert_eq!(
            load(
                &bound,
                MaterialKind::Cert,
                &[root.path().to_path_buf()],
                1024
            )
            .unwrap()
            .bytes
            .expose_secret(),
            b"rotated in-root bytes"
        );
    }

    #[test]
    fn windows_preexisting_data_write_or_delete_handles_refuse_until_closed() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let file = nested.join("cert.pem");
        std::fs::write(&file, INLINE_CERT).unwrap();
        let checked = std::fs::canonicalize(&file).unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        // Both leaf and ancestor are checked. WRITE_DATA (ADD_FILE for a
        // directory) and DELETE handles opened before the walk must conflict
        // with its restrictive sharing, even when they themselves share all.
        for target in [&file, &nested] {
            for access in [0x0002, 0x0001_0000] {
                let prior = std::fs::OpenOptions::new()
                    .access_mode(access)
                    .share_mode(7)
                    .custom_flags(0x0200_0000)
                    .open(target)
                    .unwrap();
                assert!(open(&canonical_root, &checked).is_err());
                drop(prior);
                let mut handle = open(&canonical_root, &checked).unwrap();
                let mut bytes = Vec::new();
                handle.read_to_end(&mut bytes).unwrap();
                assert_eq!(bytes, INLINE_CERT.as_bytes());
            }
        }
    }

    #[test]
    fn windows_attribute_only_retag_race_never_returns_outside_file() {
        use std::os::windows::fs::OpenOptionsExt;
        use std::sync::{Arc, Barrier};
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let nested = root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let file = nested.join("cert.pem");
        std::fs::write(&file, INLINE_CERT).unwrap();
        std::fs::write(outside.path().join("cert.pem"), b"outside private bytes").unwrap();
        let checked = std::fs::canonicalize(&file).unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        // This deliberately holds ONLY WRITE_ATTRIBUTES, which is not excluded
        // by write/delete sharing. An empty physical directory can be retagged
        // while the secure opener inspects/traverses its directory handle.
        let attributes = std::fs::OpenOptions::new()
            .access_mode(0x0100)
            .share_mode(7)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(&nested)
            .unwrap();
        std::fs::remove_file(&file).unwrap();
        let set = junction_buffer(outside.path());
        let delete = [0x03, 0x00, 0x00, 0xa0, 0, 0, 0, 0];
        // Establish this real kernel capability first; failure is a failed
        // security gate, never a silently skipped/passing race regression.
        reparse_control(&attributes, 0x0009_00a4, &set)
            .expect("NTFS attribute-only reparse mutation gate");
        assert!(open(&canonical_root, &checked).is_err());
        reparse_control(&attributes, 0x0009_00ac, &delete).unwrap();
        let start = Arc::new(Barrier::new(2));
        let end = Arc::new(Barrier::new(2));
        let worker_start = Arc::clone(&start);
        let worker_end = Arc::clone(&end);
        let worker = std::thread::spawn(move || {
            let mut errors = Vec::new();
            for _ in 0..128 {
                worker_start.wait();
                if let Err(error) = reparse_control(&attributes, 0x0009_00a4, &set)
                    // A competing checked handle can safely deny mutation.
                    && !matches!(error.raw_os_error(), Some(5 | 32))
                {
                    errors.push(error);
                }
                std::thread::yield_now();
                if let Err(error) = reparse_control(&attributes, 0x0009_00ac, &delete)
                    && !matches!(error.raw_os_error(), Some(5 | 32 | 4390))
                {
                    errors.push(error);
                }
                // Do not panic before this barrier, leaving the opener parked.
                worker_end.wait();
            }
            errors
        });
        let mut unexpected_open = false;
        for _ in 0..128 {
            start.wait();
            // The physical in-root leaf is absent. A successful open would
            // necessarily be a followed outside target, irrespective of bytes.
            unexpected_open |= open(&canonical_root, &checked).is_ok();
            end.wait();
        }
        let errors = worker.join().unwrap();
        assert!(
            errors.is_empty(),
            "retag fixture operations failed: {errors:?}"
        );
        assert!(
            !unexpected_open,
            "outside target opened during attribute-only retag"
        );
        let cleanup = std::fs::OpenOptions::new()
            .access_mode(0x0100)
            .share_mode(7)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(&nested)
            .unwrap();
        if let Err(error) = reparse_control(&cleanup, 0x0009_00ac, &delete) {
            assert_eq!(error.raw_os_error(), Some(4390), "reparse cleanup");
        }
        drop(cleanup);
        // Retagging completed and handles closed: ordinary in-root use recovers.
        std::fs::write(&file, INLINE_CERT).unwrap();
        let mut handle = open(&canonical_root, &checked).unwrap();
        let mut bytes = Vec::new();
        handle.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, INLINE_CERT.as_bytes());
        // This bounded concurrent campaign does not promise an exact schedule
        // between native lookup instructions; the earlier swaps are deterministic.
    }

    // Ignored in ordinary runs; `.github/workflows/windows-confinement.yml`
    // runs it explicitly on an elevated hosted Windows runner.
    #[test]
    #[ignore = "requires elevated NTFS case-sensitive-directory security gate"]
    fn windows_case_sensitive_sibling_is_not_an_allowed_root_alias() {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn SetFileInformationByHandle(
                file: *mut std::ffi::c_void,
                class: i32,
                information: *const std::ffi::c_void,
                size: u32,
            ) -> i32;
        }
        let parent = tempfile::tempdir().unwrap();
        let directory = std::fs::OpenOptions::new()
            .access_mode(0x0100 | 0x0080 | 0x0002 | 0x0004 | 0x0040)
            .custom_flags(0x0200_0000)
            .open(parent.path())
            .unwrap();
        let flags = 1u32; // FILE_CS_FLAG_CASE_SENSITIVE_DIR
        // SAFETY: live owned empty directory and the documented one-u32
        // FILE_CASE_SENSITIVE_INFO layout. Unsupported/unelevated is a failure.
        let success = unsafe {
            SetFileInformationByHandle(
                directory.as_raw_handle(),
                23, // FileCaseSensitiveInfo
                (&flags as *const u32).cast(),
                std::mem::size_of::<u32>() as u32,
            )
        };
        assert_ne!(
            success,
            0,
            "case-sensitive NTFS fixture: {}",
            std::io::Error::last_os_error()
        );
        drop(directory);
        let allowed = parent.path().join("Tenant");
        let sibling = parent.path().join("tenant");
        std::fs::create_dir(&allowed).unwrap();
        std::fs::create_dir(&sibling).unwrap();
        let own = allowed.join("cert.pem");
        let foreign = sibling.join("cert.pem");
        std::fs::write(&own, INLINE_CERT).unwrap();
        std::fs::write(&foreign, b"outside private bytes").unwrap();
        let roots = [allowed];
        let own_bound = bound_file(own.to_str().unwrap(), MaterialKind::Cert);
        assert_eq!(
            load(&own_bound, MaterialKind::Cert, &roots, 1024)
                .unwrap()
                .bytes
                .expose_secret(),
            INLINE_CERT.as_bytes()
        );
        let foreign_bound = bound_file(foreign.to_str().unwrap(), MaterialKind::Cert);
        assert!(load(&foreign_bound, MaterialKind::Cert, &roots, 1024).is_err());
        assert!(
            open(
                &std::fs::canonicalize(&roots[0]).unwrap(),
                &std::fs::canonicalize(&foreign).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn windows_repeated_success_and_refusal_do_not_grow_process_handles() {
        const CHILD_ENV: &str = "FERRUM_WINDOWS_HANDLE_LEAK_CHILD";
        // `GetProcessHandleCount` observes every handle in the current process.
        // Re-execute this test alone in a dedicated child process when invoked
        // from a parallel `cargo test` run so sibling test threads cannot skew
        // the process-wide handle count.
        if std::env::var_os(CHILD_ENV).is_none() {
            let exe = std::env::current_exe().unwrap();
            let output = std::process::Command::new(exe)
                .env(CHILD_ENV, "1")
                .args([
                    "--exact",
                    "windows_confined_files::windows_repeated_success_and_refusal_do_not_grow_process_handles",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated handle-leak child failed ({}):\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetCurrentProcess() -> *mut std::ffi::c_void;
            fn GetProcessHandleCount(process: *mut std::ffi::c_void, count: *mut u32) -> i32;
        }
        fn handle_count() -> u32 {
            let mut count = 0;
            // SAFETY: current-process pseudo handle is borrowed, never closed;
            // the API fills one valid u32. Executed inside an isolated single-test
            // child process above.
            assert_ne!(
                unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) },
                0
            );
            count
        }
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("cert.pem");
        std::fs::write(&file, INLINE_CERT).unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        let checked = std::fs::canonicalize(&file).unwrap();
        let before = handle_count();
        for _ in 0..128 {
            drop(open(&canonical_root, &checked).unwrap());
            assert!(
                open(
                    &canonical_root,
                    &canonical_root.join("missing").join("cert.pem")
                )
                .is_err()
            );
            assert!(open(&canonical_root, &checked.join("child")).is_err());
            assert!(open(&canonical_root, &canonical_root).is_err());
        }
        assert!(
            handle_count() <= before,
            "secure opens leaked process handles"
        );
        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn windows_bounds_nonregular_traversal_and_streams_fail_closed_without_handle_leaks() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("cert.pem");
        std::fs::write(&file, INLINE_CERT).unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        let bound = bound_file(file.to_str().unwrap(), MaterialKind::Cert);
        assert!(matches!(
            load(&bound, MaterialKind::Cert, &[root.path().to_path_buf()], 4),
            Err(ferrum_edge::tls::source::MaterialError::Oversized { .. })
        ));
        assert!(open(&canonical_root, &canonical_root).is_err());
        let directory = root.path().join("directory.pem");
        std::fs::create_dir(&directory).unwrap();
        assert!(open(&canonical_root, &canonical_root.join("directory.pem")).is_err());
        std::fs::remove_dir(&directory).unwrap();
        assert!(
            open(
                &canonical_root,
                &canonical_root.join("cert.pem").join("child")
            )
            .is_err()
        );
        assert!(open(&canonical_root, &canonical_root.join("..\\outside.pem")).is_err());
        assert!(open(&canonical_root, &canonical_root.join("cert.pem:private")).is_err());
        assert!(open(&canonical_root, &canonical_root.join("nul\0.pem")).is_err());
        let canonical_file = std::fs::canonicalize(&file).unwrap();
        assert!(open(&canonical_file, &canonical_file.join("child")).is_err());
        // WRITE/DELETE would fail if any refused open leaked a held file handle.
        std::fs::remove_file(&file).unwrap();
    }
}
