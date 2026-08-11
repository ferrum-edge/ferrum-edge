//! The check-to-connect boundary of the Sidecar ingress Unix transport
//! (issue #3261).
//!
//! Path admission alone cannot be atomic with `connect(2)`, so the transport
//! binds the CONNECTION to the identity admission checked: the connected peer's
//! uid must equal the checked socket owner's uid, and the checked path must
//! still name the checked inode. Both assertions run after `connect(2)` and
//! BEFORE any request byte is written, which is the property these tests prove —
//! each substituted peer accepts the connection and then observes that zero
//! bytes ever arrive.

#![cfg(unix)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::config::types::UpstreamTarget;
use ferrum_edge::proxy::unix_backend::{
    DEFAULT_UNIX_CONNECT_TIMEOUT_MS, MESH_UNIX_SOCKET_H2C_TAG, MESH_UNIX_SOCKET_TAG,
    UnixBackendError, connect_admitted, dial_unix_h2c_sender, effective_connect_timeout_ms,
    resolve_unix_socket_target, target_is_unix_backend,
};
use ferrum_edge::util::unix_socket::{UnixSocketPathRejection, admit_socket_for_connect};

/// A listener that accepts and then counts every byte it is ever sent.
///
/// The refusal contract is an ORDERING claim, so the substituted peer has to be
/// able to observe request bytes if any were written. Accepting (rather than
/// leaving the backlog untouched) is deliberate: the connect must succeed so
/// that the *post-connect* identity checks are what refuses.
struct CountingPeer {
    bytes: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl CountingPeer {
    fn bind(path: &Path) -> Self {
        let listener = tokio::net::UnixListener::bind(path).expect("bind substituted peer");
        let bytes = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&bytes);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                counter.fetch_add(n, Ordering::SeqCst);
                            }
                        }
                    }
                });
            }
        });
        Self { bytes, task }
    }

    fn bytes_received(&self) -> usize {
        self.bytes.load(Ordering::SeqCst)
    }
}

impl Drop for CountingPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn canonical_root(temp: &tempfile::TempDir) -> PathBuf {
    temp.path().canonicalize().expect("canonicalize temp dir")
}

fn roots(root: &Path) -> Vec<String> {
    vec![root.to_str().expect("utf-8 root").to_string()]
}

/// Give the substituted peer a moment in which it *could* have observed request
/// bytes, so "zero bytes" is evidence rather than a race the test won.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(150)).await;
}

fn tagged_target(tags: &[(&str, &str)]) -> UpstreamTarget {
    UpstreamTarget {
        host: "127.0.0.1".to_string(),
        port: 8443,
        service_port_policy_key: None,
        weight: 1,
        tags: tags
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect::<HashMap<_, _>>(),
        locality: None,
        path: None,
    }
}

#[test]
fn an_unset_unix_connect_timeout_keeps_a_bounded_default() {
    assert_eq!(
        effective_connect_timeout_ms(0),
        DEFAULT_UNIX_CONNECT_TIMEOUT_MS
    );
    assert_eq!(effective_connect_timeout_ms(321), 321);
}

/// Either half of the Unix transport identity reserves the target. A carrier
/// that loses only the primary path tag must be refused, never downgraded to
/// the placeholder TCP address.
#[test]
fn a_lone_h2c_marker_fails_closed_as_a_malformed_unix_target() {
    let target = tagged_target(&[(MESH_UNIX_SOCKET_H2C_TAG, "true")]);
    assert!(target_is_unix_backend(&target));
    assert_eq!(
        resolve_unix_socket_target(&target, &["/run/ferrum".to_string()]),
        Some(Err(UnixSocketPathRejection::MissingSocketPathTag))
    );
}

/// The wire protocol is part of the transport identity, not an optional hint.
/// Losing it must not turn an h2c backend into an HTTP/1.1 backend.
#[test]
fn a_lone_socket_path_marker_fails_closed_without_a_wire_protocol() {
    let target = tagged_target(&[(MESH_UNIX_SOCKET_TAG, "/run/ferrum/app.sock")]);
    assert!(target_is_unix_backend(&target));
    assert_eq!(
        resolve_unix_socket_target(&target, &["/run/ferrum".to_string()]),
        Some(Err(UnixSocketPathRejection::MissingWireProtocolTag))
    );
}

#[test]
fn a_malformed_wire_protocol_marker_fails_closed() {
    let target = tagged_target(&[
        (MESH_UNIX_SOCKET_TAG, "/run/ferrum/app.sock"),
        (MESH_UNIX_SOCKET_H2C_TAG, "yes"),
    ]);
    assert_eq!(
        resolve_unix_socket_target(&target, &["/run/ferrum".to_string()]),
        Some(Err(UnixSocketPathRejection::InvalidWireProtocolTag))
    );
}

/// Reserved mesh transport identities are mutually exclusive. In particular,
/// a carrier must not be able to make call-site ordering choose Unix instead
/// of an mTLS/HBONE boundary (or vice versa).
#[test]
fn mixed_reserved_mesh_transport_tags_are_rejected() {
    let target = tagged_target(&[
        (MESH_UNIX_SOCKET_TAG, "/run/ferrum/app.sock"),
        (MESH_UNIX_SOCKET_H2C_TAG, "false"),
        ("mesh.mtls", "true"),
    ]);
    assert_eq!(
        resolve_unix_socket_target(&target, &["/run/ferrum".to_string()]),
        Some(Err(UnixSocketPathRejection::ConflictingTransportTags))
    );
}

/// THE CHECK-TO-CONNECT SWAP, deterministically: admit socket A, replace the
/// path with a different socket B, then dial the admitted identity. The connect
/// succeeds — B really is listening — but the inode no longer matches what was
/// checked, so the stream is dropped unused and B never sees a request byte.
///
/// B is bound by this same process, so its owner and peer uid are identical to
/// A's: the refusal here is the INODE identity check specifically, which is the
/// only thing that can catch a same-uid substitution.
#[tokio::test]
async fn a_socket_swapped_after_admission_is_refused_before_any_request_byte() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = canonical_root(&temp);
    let path = root.join("app.sock");

    let _original = std::os::unix::net::UnixListener::bind(&path).expect("bind original socket");
    let admitted = admit_socket_for_connect(path.to_str().expect("utf-8"), &roots(&root), &[])
        .expect("the original socket is admitted");

    // The swap: unlink the admitted socket and bind a different object at the
    // same path. Exactly what an attacker with write access to the directory
    // would do inside the check-to-connect window.
    std::fs::remove_file(&path).expect("unlink the admitted socket");
    let substituted = CountingPeer::bind(&path);

    let outcome = connect_admitted(&admitted, 2_000).await;
    assert!(
        matches!(outcome, Err(UnixBackendError::SocketIdentityChanged)),
        "a swapped socket must be refused as an identity change, got {outcome:?}"
    );

    settle().await;
    assert_eq!(
        substituted.bytes_received(),
        0,
        "the substituted peer must never receive a request byte"
    );
}

/// The connected-peer credential gate uses exact checked-owner equality, not
/// membership in the broader configured allowlist. Exercise that comparison on
/// an identity returned by real admission rather than exposing a constructor
/// that could fabricate the security type.
#[test]
fn connected_peer_uid_must_exactly_match_the_checked_owner() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = canonical_root(&temp);
    let path = root.join("app.sock");
    let _peer = std::os::unix::net::UnixListener::bind(&path).expect("bind socket");
    let admitted = admit_socket_for_connect(path.to_str().expect("utf-8"), &roots(&root), &[])
        .expect("the socket is admitted");

    // SAFETY: `geteuid` takes no arguments, reads process state, never fails.
    let euid = unsafe { libc::geteuid() };
    let foreign_uid = euid.wrapping_add(1);
    assert!(
        !admitted.peer_uid_matches(foreign_uid),
        "a different allowlisted uid must not match this checked socket owner"
    );
    assert!(
        admitted.peer_uid_matches(euid),
        "the checked socket owner must match exactly"
    );
}

/// A socket that vanishes inside the window is identity ambiguity, and ambiguity
/// fails closed rather than dialing whatever appears next.
#[tokio::test]
async fn an_unlinked_socket_is_refused_rather_than_dialed_blind() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = canonical_root(&temp);
    let path = root.join("app.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind socket");
    let admitted = admit_socket_for_connect(path.to_str().expect("utf-8"), &roots(&root), &[])
        .expect("the socket is admitted");

    drop(listener);
    std::fs::remove_file(&path).expect("unlink socket");

    let outcome = connect_admitted(&admitted, 2_000).await;
    assert!(
        matches!(outcome, Err(UnixBackendError::Connect(_))),
        "an absent socket must fail closed at connect, got {outcome:?}"
    );
}

/// An admitted peer may accept the Unix connection and then never speak h2c.
///
/// Hyper's `handshake()` writes only the CLIENT preface and never reads, so it
/// completes against this peer; establishment is the PEER's initial SETTINGS
/// frame, and the connect budget has to bound waiting for it. Without that bound
/// the sender would be handed to dispatch and the request would park on a
/// response that never comes — forever, when the client supplied no gRPC
/// deadline and no backend read timeout is configured.
///
/// The wall-clock assertions are the contract: the dial must actually spend the
/// budget (not refuse early for some unrelated reason) and must not wait on the
/// peer, which holds the connection open far longer than the budget.
#[tokio::test]
async fn a_stalled_h2c_handshake_is_bounded_by_the_connect_budget() {
    const BUDGET_MS: u64 = 200;

    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = canonical_root(&temp);
    let path = root.join("stalled-h2c.sock");
    let listener = tokio::net::UnixListener::bind(&path).expect("bind h2c socket");
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept h2c connection");
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(stream);
    });

    let started = std::time::Instant::now();
    let outcome = dial_unix_h2c_sender(
        path.to_str().expect("utf-8 socket path"),
        BUDGET_MS,
        &roots(&root),
        &[],
    )
    .await;
    let elapsed = started.elapsed();
    match outcome {
        Err(UnixBackendError::H2HandshakeTimeout { timeout_ms }) => {
            assert_eq!(timeout_ms, BUDGET_MS);
        }
        Err(other) => panic!("expected a bounded h2c handshake timeout, got {other:?}"),
        Ok(_) => panic!("a peer that withholds its SETTINGS preface must not establish h2c"),
    }
    assert!(
        elapsed >= Duration::from_millis(150),
        "the dial must spend the connect budget waiting for the peer preface, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the dial must not outlive the connect budget, took {elapsed:?}"
    );
    peer.abort();
}

/// The establishment gate is not a blanket refusal. A peer that DOES send its
/// RFC 9113 §3.4 connection preface — a well-formed initial SETTINGS frame on
/// stream 0 — is accepted, and the sender comes back inside the budget.
///
/// Without this the timeout contract above would also be satisfied by a
/// transport that never establishes anything at all.
#[tokio::test]
async fn a_peer_that_sends_its_settings_preface_establishes_the_h2c_dial() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = canonical_root(&temp);
    let path = root.join("live-h2c.sock");
    let listener = tokio::net::UnixListener::bind(&path).expect("bind h2c socket");
    let peer = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = listener.accept().await.expect("accept h2c connection");
        // The server connection preface: an empty SETTINGS frame. 9-byte header,
        // 24-bit length 0, type 0x4, no flags, stream identifier 0.
        stream
            .write_all(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0])
            .await
            .expect("write the server SETTINGS preface");
        stream.flush().await.expect("flush the server preface");
        // Keep draining so the client's own preface and SETTINGS ACK cannot
        // stall against a full socket buffer while the dial completes.
        let mut sink = [0u8; 1024];
        while stream.read(&mut sink).await.unwrap_or(0) > 0 {}
    });

    let outcome = dial_unix_h2c_sender(
        path.to_str().expect("utf-8 socket path"),
        5_000,
        &roots(&root),
        &[],
    )
    .await;
    match outcome {
        Ok(_sender) => {}
        Err(err) => panic!("an established h2c peer must be accepted, got {err:?}"),
    }
    peer.abort();
}
