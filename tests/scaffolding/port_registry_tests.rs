//! Regression coverage for nextest's one-test-per-process port handoff.

use super::port_registry::{PortLease, PortRegistry, TestSocket};
use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

// Synthetic candidates isolate the registry invariant from OS port availability.
// With the old bind/drop allocator both owners always select the first candidate.
fn lease(registry: &Arc<PortRegistry>) -> io::Result<PortLease> {
    registry
        .lease_with(41_000..=41_002, |port| Ok((port, ())))
        .map(|(lease, ())| lease)
}

#[test]
fn multi_port_allocation_is_distinct_and_exhaustion_is_explicit() {
    let directory = tempfile::tempdir().unwrap();
    let registry = PortRegistry::new(directory.path()).unwrap();
    let leases: Vec<_> = (0..3).map(|_| lease(&registry).unwrap()).collect();
    let ports: BTreeSet<_> = leases.iter().map(|lease| lease.port).collect();
    assert_eq!(ports.len(), 3);
    assert_eq!(
        lease(&registry).err().unwrap().kind(),
        io::ErrorKind::AddrInUse
    );
}

#[test]
fn lease_is_released_on_drop() {
    let directory = tempfile::tempdir().unwrap();
    let first = PortRegistry::new(directory.path()).unwrap();
    let second = PortRegistry::new(directory.path()).unwrap();
    let held = lease(&first).unwrap();
    let port = held.port;
    let other = lease(&second).unwrap();
    assert_ne!(port, other.port);
    drop(held);
    assert_eq!(lease(&second).unwrap().port, port);
}

struct RegistryChild(Child);

impl Drop for RegistryChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn cross_process_leases_survive_handoff_and_reclaim_after_exit() {
    let directory = tempfile::tempdir().unwrap();
    let registry = PortRegistry::new(directory.path()).unwrap();
    let first = lease(&registry).unwrap();
    let second = lease(&registry).unwrap();
    assert_eq!((first.port, second.port), (41_000, 41_001));

    let mut child = RegistryChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "scaffolding::port_registry_tests::port_registry_child",
                "--nocapture",
            ])
            .env("TEST_PORT_REGISTRY_CHILD", directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn independent test allocator"),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let ready = directory.path().join("ready");
    while !ready.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "allocator child exited early"
        );
        assert!(
            Instant::now() < deadline,
            "allocator child did not report its lease"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(std::fs::read_to_string(ready).unwrap(), "41002");
    assert!(
        lease(&registry).is_err(),
        "child's unbound port must remain leased"
    );

    std::fs::write(directory.path().join("exit"), b"exit without destructors").unwrap();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "allocator child failed: {status}");
            break;
        }
        assert!(Instant::now() < deadline, "allocator child did not exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        lease(&registry).unwrap().port,
        41_002,
        "reclaim dead owner's lease"
    );
}

#[test]
fn port_registry_child() {
    let Some(root) = std::env::var_os("TEST_PORT_REGISTRY_CHILD") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let registry = PortRegistry::new(&root).unwrap();
    let held = lease(&registry).unwrap();
    assert_eq!(
        held.port, 41_002,
        "must skip both ports held by the other process"
    );
    let port = held.retain_for_process();
    drop(held);
    std::fs::write(root.join("ready.tmp"), port.to_string()).unwrap();
    std::fs::rename(root.join("ready.tmp"), root.join("ready")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !root.join("exit").exists() {
        assert!(
            Instant::now() < deadline,
            "parent did not release allocator child"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // Model nextest termination: no Rust destructors, but the kernel releases
    // the owner lock. The surviving allocator must reclaim the retained lease.
    std::process::exit(0);
}

#[tokio::test]
async fn socket_handoff_and_wildcard_listener_share_the_registry() {
    let reservation = super::ports::reserve_port().await.unwrap();
    let port = reservation.drop_and_take_port();
    let wildcard = tokio::net::TcpListener::bind_test(("0.0.0.0", port))
        .await
        .unwrap();
    let udp = super::ports::reserve_udp_port().await.unwrap();
    assert_ne!(
        udp.port, port,
        "TCP and UDP allocations share the lease namespace"
    );
    drop(wildcard);
    let next = super::ports::unbound_port().await.unwrap();
    assert_ne!(
        next, port,
        "dropping a native listener must preserve the handoff lease"
    );
}

#[test]
fn functional_and_integration_sockets_use_the_registry() {
    fn inspect(directory: &Path) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                inspect(&path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = std::fs::read_to_string(&path).unwrap();
                for constructor in ["TcpListener", "UdpSocket", "TcpSocket", "DtlsServer"] {
                    for method in ["bind", "bind_with_limits"] {
                        let bypass = format!("{constructor}::{method}(");
                        assert!(
                            !source.contains(&bypass),
                            "{} bypasses the shared port registry with {bypass}",
                            path.display()
                        );
                    }
                }
                assert!(
                    !uses_literal_socket_port(&source),
                    "{} uses a literal socket port instead of a registry lease",
                    path.display()
                );
            }
        }
    }
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    inspect(&tests.join("functional"));
    inspect(&tests.join("integration"));
}

/// Catch fixed ports even when a fixture uses the registry's socket API.
/// Config-only examples are allowed; a matching bind/connect is not.
fn uses_literal_socket_port(source: &str) -> bool {
    use regex::{Regex, RegexSet};
    use std::sync::LazyLock;

    static DIRECT: LazyLock<RegexSet> = LazyLock::new(|| {
        RegexSet::new([
            r"\bbind_test\s*\(\s*[1-9][0-9_]*",
            r#"\bbind_test\s*\(\s*(?:format!\s*\(\s*)?"[^"\n]*:[1-9][0-9_]*""#,
            r#"\bbind_test\s*\(\s*\(\s*[^,\n]+,\s*[1-9][0-9_]*\b"#,
            r#"\bbind_test\s*\(\s*format!\s*\(\s*"[^"\n]*"\s*,\s*[1-9][0-9_]*"#,
            r"\bstart_\w*server(?:_on)?\s*\(\s*[1-9][0-9_]*",
        ])
        .unwrap()
    });
    static CONFIG: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?m)^\s*"?(?:port|backend_port|listen_port)"?\s*:\s*([0-9_]+)"#).unwrap()
    });
    static CALL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?s)\b(?:bind_test|connect|start_\w*server(?:_on)?)\s*\(([^;]*?)\)").unwrap()
    });
    static NUMBER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b[1-9][0-9_]{3,}(?:u16)?\b").unwrap());

    if DIRECT.is_match(source) {
        return true;
    }
    let config_ports: BTreeSet<u16> = CONFIG
        .captures_iter(source)
        .filter_map(|capture| capture[1].replace('_', "").parse().ok())
        .filter(|port| *port >= 1000)
        .collect();
    CALL.captures_iter(source).any(|call| {
        NUMBER.find_iter(&call[1]).any(|number| {
            number
                .as_str()
                .trim_end_matches("u16")
                .replace('_', "")
                .parse::<u16>()
                .is_ok_and(|port| config_ports.contains(&port))
        })
    })
}

#[test]
fn literal_socket_port_guard_rejects_fixed_bind_and_config_handoffs() {
    for source in [
        r#"TcpListener::bind_test("127.0.0.1:30031").await;"#,
        r#"TcpListener::bind_test("[::1]:30031").await;"#,
        r#"UdpSocket::bind_test(("127.0.0.1", 30_031)).await;"#,
        "TcpSocket::bind_test(30031);",
        "start_identifying_server(\n    30031,\n    \"healthy-server\",\n);",
        "start_status_server(30032, \"unhealthy-server\", 500);",
        "start_echo_server_on(8080);",
        r#"TcpListener::bind_test(format!("127.0.0.1:{}", 30031)).await;"#,
        "backend_port: 30031\nTcpStream::connect((\"127.0.0.1\", 30031)).await;",
        "listen_port: 30_031\nTcpStream::connect(\"127.0.0.1:30031\").await;",
        "port: 30031\nTcpStream::connect(\n    format!(\"127.0.0.1:{}\", 30031),\n).await;",
    ] {
        assert!(
            uses_literal_socket_port(source),
            "missed fixed port: {source}"
        );
    }
}

#[test]
fn literal_socket_port_guard_allows_leases_and_config_only_examples() {
    for source in [
        r#"TcpListener::bind_test("127.0.0.1:0").await;"#,
        r#"TcpListener::bind_test("[::1]:0").await;"#,
        r#"UdpSocket::bind_test(("127.0.0.1", 0)).await;"#,
        r#"UdpSocket::bind_test(("::1", 0)).await;"#,
        r#"TcpListener::bind_test(format!("127.0.0.1:{port}")).await;"#,
        "start_identifying_server(listener, \"healthy-server\");",
        "start_status_server(listener, \"unhealthy-server\", 500);",
        "backend_port: 30031\nlisten_port: 40123\nport: 8080",
        "backend_port: 30031\nTcpStream::connect((\"127.0.0.1\", port)).await;",
        r#"TcpStream::connect("127.0.0.1:6379").await;"#,
    ] {
        assert!(
            !uses_literal_socket_port(source),
            "rejected safe source: {source}"
        );
    }
}
