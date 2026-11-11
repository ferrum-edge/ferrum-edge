//! Node-agent RPC: the thin JSON request/response the CNI binary speaks to
//! the long-lived node-agent over a Unix domain socket.
//!
//! Why a custom shape rather than reusing the on-the-wire CNI JSON? The CNI
//! binary is intentionally cheap to spawn (kubelet may invoke it dozens of
//! times per node-boot during a fast scheduling burst). Forwarding the
//! original CNI JSON would force the node-agent to re-parse `CNI_ARGS`,
//! re-derive the K8s pod identity, and re-route on `CNI_COMMAND`. The CNI
//! binary already did all of that to decide what verb to call — passing
//! the normalized identity directly keeps the node-agent simple and tight.
//!
//! Wire format: one length-prefixed JSON object per request, one
//! length-prefixed JSON object per response. The length is a 4-byte
//! big-endian `u32` of the JSON byte count, capped at `MAX_RPC_BYTES`
//! so a misbehaving caller cannot force unbounded allocation. No persistent
//! connections, no pipelining — the CNI binary opens, sends, reads, closes.
//! Cost is dominated by `fork+exec`, not by the socket.

use serde::{Deserialize, Serialize};

use crate::cni::spec::{
    CniValidAttachment, MAX_CNI_ATTACHMENT_FIELD_BYTES, ingest_valid_attachments,
    is_safe_cni_container_id, is_safe_cni_ifname, is_safe_cni_netns_path, is_safe_cni_network_name,
};

/// Hard cap on a single RPC message. ADD/DEL/CHECK/STATUS stay tiny; GC may
/// carry a bounded valid-attachment set. One MiB is deliberately above the CNI
/// stdin cap so a valid normalized request does not become oversized merely
/// because the RPC envelope adds fields, while still bounding node-agent
/// allocation.
pub const MAX_RPC_BYTES: usize = 1024 * 1024;

/// Length-prefix size in bytes (big-endian `u32` of the JSON body length).
pub const LENGTH_PREFIX_BYTES: usize = 4;

/// The verb the CNI binary is asking the node-agent to perform. Mirrors
/// the CNI `ADD`/`DEL`/`CHECK`/`STATUS`/`GC` lifecycle one-for-one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RpcVerb {
    Add,
    Del,
    Check,
    Status,
    Gc,
}

impl RpcVerb {
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Del => "del",
            Self::Check => "check",
            Self::Status => "status",
            Self::Gc => "gc",
        }
    }
}

/// Outcome label for `ferrum_node_agent_cni_calls_total{verb,outcome}`.
/// Closed set so the metric cardinality is bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcOutcome {
    Success,
    Rejected,
    Error,
}

impl RpcOutcome {
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Rejected => "rejected",
            Self::Error => "error",
        }
    }
}

/// One CNI invocation, normalized for the node-agent.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CniRpcRequest {
    pub verb: RpcVerb,
    /// CNI network configuration name. GC is authoritative only within this
    /// scope; omitting it would let one network sweep another network's claim.
    pub network_name: String,
    /// Empty on STATUS/GC (no attachment parameters).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pod_namespace: String,
    /// Empty on STATUS/GC (no attachment parameters).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pod_name: String,
    /// Optional because not every CRI surfaces `K8S_POD_UID`. When absent
    /// the node-agent reconciles via the kube-rs watcher; this just
    /// means the CNI hot path may be a no-op for that pod.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_uid: Option<String>,
    /// Empty on STATUS/GC (no attachment parameters).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub container_id: String,
    /// Interface name from `CNI_IFNAME` on ADD/DEL/CHECK. Combined with
    /// `container_id` this is the CNI attachment identity GC matches against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ifname: Option<String>,
    /// Path to the pod network namespace. Absent on DEL when the sandbox
    /// is already gone — the node-agent treats absence as "best-effort
    /// teardown by pod identity".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netns_path: Option<String>,
    /// Still-valid attachments for [`RpcVerb::Gc`]. Empty for other verbs.
    /// Already bounded/validated by the CNI binary before the RPC is sent.
    #[serde(default)]
    pub valid_attachments: Vec<CniValidAttachment>,
}

impl<'de> Deserialize<'de> for CniRpcRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireRequest {
            verb: RpcVerb,
            network_name: String,
            #[serde(default)]
            pod_namespace: String,
            #[serde(default)]
            pod_name: String,
            #[serde(default)]
            pod_uid: Option<String>,
            #[serde(default)]
            container_id: String,
            #[serde(default)]
            ifname: Option<String>,
            #[serde(default)]
            netns_path: Option<String>,
            #[serde(
                default,
                deserialize_with = "crate::util::json_object::deserialize_optional_object_vec"
            )]
            valid_attachments: Option<Vec<CniValidAttachment>>,
        }

        let wire = WireRequest::deserialize(deserializer)?;
        if wire.verb == RpcVerb::Gc && wire.valid_attachments.is_none() {
            return Err(serde::de::Error::missing_field("valid_attachments"));
        }
        Ok(Self {
            verb: wire.verb,
            network_name: wire.network_name,
            pod_namespace: wire.pod_namespace,
            pod_name: wire.pod_name,
            pod_uid: wire.pod_uid,
            container_id: wire.container_id,
            ifname: wire.ifname,
            netns_path: wire.netns_path,
            valid_attachments: wire.valid_attachments.unwrap_or_default(),
        })
    }
}

impl CniRpcRequest {
    /// Revalidate the complete request at the node-agent boundary. The short-
    /// lived CNI binary performs the same checks for operator feedback, but the
    /// UDS peer is not trusted to have used that binary.
    pub fn validate(&self) -> Result<(), String> {
        if !is_safe_cni_network_name(&self.network_name) {
            return Err("invalid CNI network name".to_string());
        }

        if matches!(self.verb, RpcVerb::Gc | RpcVerb::Status) {
            if !self.pod_namespace.is_empty()
                || !self.pod_name.is_empty()
                || self.pod_uid.is_some()
                || !self.container_id.is_empty()
                || self.ifname.is_some()
                || self.netns_path.is_some()
            {
                return Err(match self.verb {
                    RpcVerb::Status => {
                        "STATUS request contains attachment-specific fields".to_string()
                    }
                    _ => "GC request contains attachment-specific fields".to_string(),
                });
            }
            if self.verb == RpcVerb::Status {
                if !self.valid_attachments.is_empty() {
                    return Err("STATUS request contains a GC attachment set".to_string());
                }
                return Ok(());
            }
            ingest_valid_attachments(self.valid_attachments.clone())
                .map(|_| ())
                .map_err(|err| err.to_string())?;
            return Ok(());
        }

        if !self.valid_attachments.is_empty() {
            return Err("non-GC request contains a GC attachment set".to_string());
        }
        if !is_safe_k8s_namespace(&self.pod_namespace) {
            return Err("invalid Kubernetes pod namespace".to_string());
        }
        if !is_safe_k8s_name(&self.pod_name) {
            return Err("invalid Kubernetes pod name".to_string());
        }
        if !is_safe_cni_container_id(&self.container_id)
            || self.container_id.len() > MAX_CNI_ATTACHMENT_FIELD_BYTES
        {
            return Err("invalid CNI container ID".to_string());
        }
        if !self.ifname.as_deref().is_some_and(is_safe_cni_ifname) {
            return Err("invalid CNI interface name".to_string());
        }
        if matches!(self.verb, RpcVerb::Add | RpcVerb::Check) && self.netns_path.is_none() {
            return Err("ADD/CHECK request is missing CNI network namespace".to_string());
        }
        if self
            .netns_path
            .as_deref()
            .is_some_and(|path| !is_safe_cni_netns_path(path))
        {
            return Err("invalid CNI network namespace path".to_string());
        }
        if self.pod_uid.as_deref().is_some_and(|uid| {
            uid.len() > MAX_CNI_ATTACHMENT_FIELD_BYTES || !is_safe_cni_container_id(uid)
        }) {
            return Err("invalid Kubernetes pod UID".to_string());
        }
        Ok(())
    }
}

fn is_safe_k8s_namespace(value: &str) -> bool {
    value.len() <= 63 && is_safe_dns_label(value)
}

fn is_safe_k8s_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    value.split('.').all(is_safe_dns_label)
}

fn is_safe_dns_label(value: &str) -> bool {
    if value.is_empty() || value.len() > 63 {
        return false;
    }
    let bytes = value.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// Node-agent response shape. We never echo back pod payload — `Ok` or
/// `Rejected` is enough for kubelet, and the CNI binary translates either
/// into a CNI spec result. `details` is optional and surfaces in CNI
/// error JSON for operator debugging.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum CniRpcResponse {
    Ok,
    Rejected { reason: String },
    Error { reason: String },
}

impl CniRpcResponse {
    pub fn outcome(&self) -> RpcOutcome {
        match self {
            Self::Ok => RpcOutcome::Success,
            Self::Rejected { .. } => RpcOutcome::Rejected,
            Self::Error { .. } => RpcOutcome::Error,
        }
    }
}

/// Encode an RPC message as length-prefixed JSON ready for socket write.
///
/// Returns an error when the body exceeds [`MAX_RPC_BYTES`]; in practice
/// this is unreachable for a well-formed CNI payload but we enforce it
/// symmetrically with the read side so we never end up writing a frame
/// that the peer would reject.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(value).map_err(|e| format!("serialize rpc: {e}"))?;
    if body.len() > MAX_RPC_BYTES {
        return Err(format!(
            "rpc body {} bytes exceeds cap {MAX_RPC_BYTES}",
            body.len()
        ));
    }
    let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + body.len());
    let len = u32::try_from(body.len()).map_err(|_| "rpc body too large for u32 prefix")?;
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Parse a body byte slice as an RPC message. Length-prefix framing is
/// handled by the caller (`client.rs` and the node-agent CNI server).
pub fn decode_body<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, String> {
    serde_json::from_slice(body).map_err(|e| format!("decode rpc: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_verb_round_trips_through_json() {
        for verb in [
            RpcVerb::Add,
            RpcVerb::Del,
            RpcVerb::Check,
            RpcVerb::Status,
            RpcVerb::Gc,
        ] {
            let json = serde_json::to_string(&verb).expect("serialize");
            let back: RpcVerb = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(verb, back);
        }
    }

    #[test]
    fn rpc_request_optional_fields_skip_serializing_when_none() {
        let req = CniRpcRequest {
            verb: RpcVerb::Add,
            network_name: "ferrum-mesh".to_string(),
            pod_namespace: "demo".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: None,
            container_id: "abc".to_string(),
            ifname: None,
            netns_path: None,
            valid_attachments: Vec::new(),
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(!json.contains("pod_uid"));
        assert!(!json.contains("netns_path"));
        assert!(!json.contains("ifname"));
        assert!(json.contains(r#""valid_attachments":[]"#));
    }

    #[test]
    fn rpc_gc_request_carries_valid_attachments() {
        let req = CniRpcRequest {
            verb: RpcVerb::Gc,
            network_name: "ferrum-mesh".to_string(),
            pod_namespace: String::new(),
            pod_name: String::new(),
            pod_uid: None,
            container_id: String::new(),
            ifname: None,
            netns_path: None,
            valid_attachments: vec![CniValidAttachment {
                container_id: "ctr-1".to_string(),
                ifname: "eth0".to_string(),
            }],
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let back: CniRpcRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.verb, RpcVerb::Gc);
        assert_eq!(back.valid_attachments.len(), 1);
        assert_eq!(back.valid_attachments[0].container_id, "ctr-1");
    }

    #[test]
    fn rpc_gc_request_rejects_omitted_valid_attachments() {
        let json = r#"{"verb":"gc","network_name":"ferrum-cni"}"#;
        let err = serde_json::from_str::<CniRpcRequest>(json)
            .expect_err("GC must carry an explicit authoritative attachment set");
        assert!(err.to_string().contains("valid_attachments"));
    }

    #[test]
    fn rpc_response_tag_round_trip() {
        let ok = CniRpcResponse::Ok;
        let json = serde_json::to_string(&ok).expect("serialize");
        assert_eq!(json, r#"{"status":"ok"}"#);
        let rejected = CniRpcResponse::Rejected {
            reason: "excluded namespace".to_string(),
        };
        let json = serde_json::to_string(&rejected).expect("serialize");
        let back: CniRpcResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, rejected);
        let err = CniRpcResponse::Error {
            reason: "backend exploded".to_string(),
        };
        assert_eq!(err.outcome(), RpcOutcome::Error);
        assert_eq!(rejected.outcome(), RpcOutcome::Rejected);
        assert_eq!(ok.outcome(), RpcOutcome::Success);
    }

    #[test]
    fn encode_frame_includes_length_prefix() {
        let req = CniRpcRequest {
            verb: RpcVerb::Del,
            network_name: "ferrum-mesh".to_string(),
            pod_namespace: "demo".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: None,
            container_id: "abc".to_string(),
            ifname: None,
            netns_path: None,
            valid_attachments: Vec::new(),
        };
        let frame = encode_frame(&req).expect("encode");
        assert!(frame.len() > LENGTH_PREFIX_BYTES);
        let len_bytes: [u8; 4] = frame[..LENGTH_PREFIX_BYTES]
            .try_into()
            .expect("prefix slice");
        let prefix_len = u32::from_be_bytes(len_bytes) as usize;
        assert_eq!(prefix_len + LENGTH_PREFIX_BYTES, frame.len());
        let body = &frame[LENGTH_PREFIX_BYTES..];
        let decoded: CniRpcRequest = decode_body(body).expect("decode body");
        assert_eq!(decoded, req);
    }

    #[test]
    fn encode_frame_rejects_oversized_payload() {
        let huge_value = "x".repeat(MAX_RPC_BYTES + 1);
        let req = CniRpcRequest {
            verb: RpcVerb::Add,
            network_name: "ferrum-mesh".to_string(),
            pod_namespace: huge_value,
            pod_name: "alpha".to_string(),
            pod_uid: None,
            container_id: "abc".to_string(),
            ifname: None,
            netns_path: None,
            valid_attachments: Vec::new(),
        };
        let err = encode_frame(&req).expect_err("oversized payload should reject");
        assert!(
            err.contains("exceeds cap"),
            "expected size-cap error, got: {err}"
        );
    }

    #[test]
    fn rpc_verb_metric_labels_are_lowercase() {
        assert_eq!(RpcVerb::Add.metric_label(), "add");
        assert_eq!(RpcVerb::Del.metric_label(), "del");
        assert_eq!(RpcVerb::Check.metric_label(), "check");
        assert_eq!(RpcVerb::Status.metric_label(), "status");
        assert_eq!(RpcVerb::Gc.metric_label(), "gc");
    }

    #[test]
    fn rpc_outcome_metric_labels_form_closed_set() {
        assert_eq!(RpcOutcome::Success.metric_label(), "success");
        assert_eq!(RpcOutcome::Rejected.metric_label(), "rejected");
        assert_eq!(RpcOutcome::Error.metric_label(), "error");
    }
}
