//! xDS compatibility facade over the shared CP gRPC admission controller.
//!
//! The layered accounting lives in [`crate::grpc::admission`]. This facade
//! retains the xDS public names, ADS-only active gauges, and ADS node-state
//! cleanup semantics while production shares the underlying total,
//! namespace, principal, node, and node-cardinality budgets with native
//! ConfigSync and MeshSubscribe streams.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

pub use crate::grpc::admission::{
    CpGrpcAdmissionLimits as XdsAdmissionLimits, CpGrpcAdmissionRejection as XdsAdmissionRejection,
    DEFAULT_CP_GRPC_MAX_ACTIVE_NODES as DEFAULT_XDS_MAX_ACTIVE_NODES,
    DEFAULT_CP_GRPC_MAX_NODE_ID_BYTES as DEFAULT_XDS_MAX_NODE_ID_BYTES,
    DEFAULT_CP_GRPC_MAX_STREAMS_PER_NAMESPACE as DEFAULT_XDS_MAX_STREAMS_PER_NAMESPACE,
    DEFAULT_CP_GRPC_MAX_STREAMS_PER_NODE as DEFAULT_XDS_MAX_STREAMS_PER_NODE,
    DEFAULT_CP_GRPC_MAX_STREAMS_PER_PRINCIPAL as DEFAULT_XDS_MAX_STREAMS_PER_PRINCIPAL,
    DEFAULT_CP_GRPC_MAX_TOTAL_STREAMS as DEFAULT_XDS_MAX_TOTAL_STREAMS,
    DEFAULT_XDS_FIRST_REQUEST_TIMEOUT_SECS, principal_key, redacted_identifier, validate_node_id,
};

use crate::grpc::admission::{CpGrpcAdmissionController, CpGrpcStreamPermit, node_state_key};

/// Preserve the historical xDS state-key helper and byte-for-byte key shape.
pub fn xds_state_key(namespace: &str, principal_key: &str, node_id: &str) -> String {
    node_state_key(namespace, principal_key, node_id)
}

/// ADS view over one process-wide CP gRPC controller.
#[derive(Debug, Clone)]
pub struct XdsAdmissionController {
    shared: CpGrpcAdmissionController,
    xds_streams: Arc<AtomicUsize>,
    xds_nodes: Arc<DashMap<String, usize>>,
}

impl XdsAdmissionController {
    pub fn new(limits: XdsAdmissionLimits) -> Self {
        Self::from_shared(CpGrpcAdmissionController::new(limits))
    }

    /// Attach ADS-specific lifecycle observation to the shared controller.
    pub fn from_shared(shared: CpGrpcAdmissionController) -> Self {
        Self {
            shared,
            xds_streams: Arc::new(AtomicUsize::new(0)),
            xds_nodes: Arc::new(DashMap::new()),
        }
    }

    pub fn shared(&self) -> CpGrpcAdmissionController {
        self.shared.clone()
    }

    pub fn limits(&self) -> &XdsAdmissionLimits {
        self.shared.limits()
    }

    pub fn active_streams(&self) -> usize {
        self.xds_streams.load(Ordering::Acquire)
    }

    pub fn active_nodes(&self) -> usize {
        self.xds_nodes.len()
    }

    pub fn tracked_namespaces(&self) -> usize {
        self.shared.tracked_namespaces()
    }

    pub fn tracked_principals(&self) -> usize {
        self.shared.tracked_principals()
    }

    pub fn namespace_streams(&self, namespace: &str) -> usize {
        self.shared.namespace_streams(namespace)
    }

    pub fn principal_streams(&self, principal_key: &str) -> usize {
        self.shared.principal_streams(principal_key)
    }

    pub fn node_streams(&self, node_key: &str) -> usize {
        self.shared.node_streams(node_key)
    }

    pub fn validate_node_id(&self, node_id: &str) -> Result<(), XdsAdmissionRejection> {
        self.shared.validate_node_id(node_id)
    }

    pub fn reserve_stream(
        &self,
        namespace: &str,
        principal_key: &str,
    ) -> Result<XdsStreamPermit, XdsAdmissionRejection> {
        let permit = self.shared.reserve_stream(namespace, principal_key)?;
        self.xds_streams.fetch_add(1, Ordering::AcqRel);
        crate::plugins::mesh::prometheus_helpers::adjust_xds_active_streams(1);
        Ok(XdsStreamPermit {
            controller: self.clone(),
            permit,
            node_key: None,
        })
    }

    fn register_xds_node(&self, node_key: &str) {
        match self.xds_nodes.entry(node_key.to_string()) {
            Entry::Occupied(mut entry) => *entry.get_mut() += 1,
            Entry::Vacant(entry) => {
                entry.insert(1);
                crate::plugins::mesh::prometheus_helpers::adjust_xds_active_node_ids(1);
            }
        }
    }

    fn unregister_xds_node_with_cleanup<F>(&self, node_key: &str, cleanup: F) -> bool
    where
        F: FnOnce(),
    {
        match self.xds_nodes.entry(node_key.to_string()) {
            Entry::Occupied(mut entry) if *entry.get() > 1 => {
                *entry.get_mut() -= 1;
                false
            }
            Entry::Occupied(entry) => {
                cleanup();
                entry.remove();
                crate::plugins::mesh::prometheus_helpers::adjust_xds_active_node_ids(-1);
                true
            }
            Entry::Vacant(_) => false,
        }
    }
}

/// ADS permit backed by the shared CP gRPC RAII permit.
#[derive(Debug)]
pub struct XdsStreamPermit {
    controller: XdsAdmissionController,
    permit: CpGrpcStreamPermit,
    node_key: Option<String>,
}

impl XdsStreamPermit {
    pub fn register_node(&mut self, node_key: &str) -> Result<(), XdsAdmissionRejection> {
        if self.node_key.as_deref() == Some(node_key) {
            return Ok(());
        }
        let _ = self.release_node();
        self.permit.register_node(node_key)?;
        self.controller.register_xds_node(node_key);
        self.node_key = Some(node_key.to_string());
        Ok(())
    }

    pub fn release_node(&mut self) -> bool {
        self.release_node_with_cleanup(|| {})
    }

    pub(crate) fn release_node_with_cleanup<F>(&mut self, cleanup: F) -> bool
    where
        F: FnOnce(),
    {
        let Some(node_key) = self.node_key.take() else {
            return false;
        };
        let last = self
            .controller
            .unregister_xds_node_with_cleanup(&node_key, cleanup);
        let _ = self.permit.release_node();
        last
    }

    pub fn limits(&self) -> &XdsAdmissionLimits {
        self.permit.limits()
    }
}

impl Drop for XdsStreamPermit {
    fn drop(&mut self) {
        let _ = self.release_node();
        let _ = self.controller.xds_streams.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| Some(current.saturating_sub(1)),
        );
        crate::plugins::mesh::prometheus_helpers::adjust_xds_active_streams(-1);
    }
}
