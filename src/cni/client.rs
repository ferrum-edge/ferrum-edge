//! Tiny synchronous Unix-domain-socket client for the CNI binary.
//!
//! The CNI binary is a short-lived `fork+exec` invocation, so we use the
//! standard library's blocking `UnixStream` rather than dragging tokio's
//! runtime into the binary. Spawning a tokio runtime for one round-trip
//! would add 1-5 ms of startup overhead per kubelet invocation — exactly
//! the kind of latency we are trying to keep CNI plugins cheap to avoid.
//!
//! Failure model: any connection / IO / decode error surfaces as
//! [`CniError::IpcFailed`] which the CNI binary reports back to kubelet
//! as CNI error code 11. That is the deliberate fail-closed ADD posture
//! (issue #3609): while a chained conflist is installed, an unreachable
//! node-agent leaves new pods in `ContainerCreating` rather than starting
//! them outside the mesh. The kube-rs watcher still reconciles pods that
//! already have a sandbox; it cannot create one. Do not turn IPC failure
//! into an unauthenticated pass-through.

use std::io::{Read, Write};
use std::time::Duration;

use crate::cni::rpc::{
    CniRpcRequest, CniRpcResponse, LENGTH_PREFIX_BYTES, MAX_RPC_BYTES, decode_body, encode_frame,
};
use crate::cni::spec::CniError;

/// Hard ceiling on a single RPC round-trip from the CNI binary. CNI plugins
/// run during sandbox setup and kubelet has its own per-plugin timeout
/// (60s default) — keeping this well under that lets the binary report a
/// clean IPC error and let kubelet retry rather than getting killed by
/// the runtime mid-call.
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Send one RPC request and read the response on a fresh connection.
///
/// The CNI binary calls this exactly once per invocation. There is no
/// connection pooling — UDS connect on a local socket is ~100 microseconds,
/// well within the budget we have, and the simplicity buys us a stateless
/// client we can drive from a non-async context.
///
/// All errors are normalized to [`CniError`] so the binary's main function
/// can map them uniformly to CNI stdout JSON + exit code.
#[cfg(unix)]
pub fn send_rpc(
    socket_path: &str,
    request: &CniRpcRequest,
    timeout: Duration,
) -> Result<CniRpcResponse, CniError> {
    use std::os::unix::net::UnixStream;

    let frame = encode_frame(request).map_err(CniError::IpcFailed)?;
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        // The configured socket can contain host filesystem details.  Keep
        // the CNI stdout error actionable without echoing that path to the
        // container runtime or its logs.
        CniError::IpcFailed(format!("connect failed: {:?}", e.kind()))
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| CniError::IpcFailed(format!("set_read_timeout: {e}")))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| CniError::IpcFailed(format!("set_write_timeout: {e}")))?;
    stream
        .write_all(&frame)
        .map_err(|e| CniError::IpcFailed(format!("write request: {e}")))?;

    let mut len_buf = [0u8; LENGTH_PREFIX_BYTES];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| CniError::IpcFailed(format!("read length prefix: {e}")))?;
    let body_len = u32::from_be_bytes(len_buf) as usize;
    if body_len > MAX_RPC_BYTES {
        return Err(CniError::IpcFailed(format!(
            "response body {body_len} bytes exceeds cap {MAX_RPC_BYTES}"
        )));
    }
    let mut body = vec![0u8; body_len];
    stream
        .read_exact(&mut body)
        .map_err(|e| CniError::IpcFailed(format!("read body: {e}")))?;

    decode_body::<CniRpcResponse>(&body).map_err(CniError::IpcFailed)
}

/// Non-Unix stub so the crate compiles on macOS/Windows for tests.
/// The CNI binary is Linux-only by design (CNI is a Linux concept), but
/// keeping this stub means contributors on a Mac can still run the
/// library tests without conditional compilation rippling through the
/// rest of the codebase.
#[cfg(not(unix))]
pub fn send_rpc(
    _socket_path: &str,
    _request: &CniRpcRequest,
    _timeout: Duration,
) -> Result<CniRpcResponse, CniError> {
    Err(CniError::IpcFailed(
        "CNI client is only implemented on Unix targets".to_string(),
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::cni::rpc::{CniRpcRequest, CniRpcResponse, RpcVerb};
    use std::collections::HashMap;
    use std::os::unix::net::UnixListener;
    use std::thread;

    /// Pure unit test: round-trip an RPC through a synchronous server stub
    /// to confirm encode/decode + length-framing line up. This is
    /// intentionally NOT spinning up tokio — the CNI binary uses a
    /// blocking client, and verifying the wire format does not need an
    /// async runtime.
    #[test]
    fn send_rpc_round_trips_with_blocking_server() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("agent.sock");
        let socket_path_str = socket_path.to_string_lossy().to_string();
        let listener = UnixListener::bind(&socket_path).expect("bind UDS");

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut len_buf = [0u8; LENGTH_PREFIX_BYTES];
            stream.read_exact(&mut len_buf).expect("read length");
            let body_len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; body_len];
            stream.read_exact(&mut body).expect("read body");
            let req: CniRpcRequest = decode_body(&body).expect("decode request");
            assert_eq!(req.verb, RpcVerb::Add);
            assert_eq!(req.pod_namespace, "demo");
            let resp = CniRpcResponse::Ok;
            let frame = encode_frame(&resp).expect("encode response");
            stream.write_all(&frame).expect("write response");
        });

        let req = CniRpcRequest {
            verb: RpcVerb::Add,
            network_name: "ferrum-mesh".to_string(),
            pod_namespace: "demo".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: Some("uid-1".to_string()),
            container_id: "ctr-1".to_string(),
            ifname: None,
            netns_path: Some("/var/run/netns/cni-1".to_string()),
            args: HashMap::new(),
            valid_attachments: Vec::new(),
        };
        let resp =
            send_rpc(&socket_path_str, &req, Duration::from_secs(2)).expect("send_rpc succeeds");
        assert_eq!(resp, CniRpcResponse::Ok);
        server.join().expect("server thread");
    }

    #[test]
    fn send_rpc_reports_ipc_error_on_missing_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("does-not-exist.sock");
        let req = CniRpcRequest {
            verb: RpcVerb::Add,
            network_name: "ferrum-mesh".to_string(),
            pod_namespace: "demo".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: None,
            container_id: "ctr-1".to_string(),
            ifname: None,
            netns_path: None,
            args: HashMap::new(),
            valid_attachments: Vec::new(),
        };
        let err = send_rpc(
            &socket_path.to_string_lossy(),
            &req,
            Duration::from_millis(200),
        )
        .expect_err("connect should fail when socket is missing");
        match err {
            CniError::IpcFailed(msg) => {
                assert!(
                    msg.contains("connect"),
                    "expected connect error, got: {msg}"
                );
                assert!(
                    !msg.contains(socket_path.to_string_lossy().as_ref()),
                    "connect error must not disclose the socket path: {msg}"
                );
            }
            other => panic!("expected IpcFailed, got {other:?}"),
        }
    }
}
