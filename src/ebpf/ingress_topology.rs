//! Fail-closed validation for the NodeWaypoint inbound tc attach topology.
//!
//! A successful tc attach proves only that the named link accepts a classifier;
//! it does not prove that remote-node traffic to local pods traverses that link.
//! This module combines bounded Kubernetes node topology with bounded host route
//! and link snapshots, then requires the configured interface set to equal the
//! complete route-derived set. It never discovers an interface to attach and
//! never broadens capture beyond the operator's explicit configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::pin::Pin;

use futures_util::{Stream, StreamExt};
use k8s_openapi::api::core::v1::Node;
use kube::Api;
use kube::Client;
use kube::runtime::watcher::{self as kube_watcher, Event};

pub const MAX_CONFIGURED_INTERFACES: usize = 16;
pub const MAX_CONFIGURED_INTERFACE_BYTES: usize = 512;
/// Hard bound for the cached Kubernetes Node topology.
pub const MAX_NODES: usize = 256;
// One IPv4 and one IPv6 PodCIDR plus one authoritative InternalIP in each
// family is the supported dual-stack worst case for every bounded Node.
const MAX_REQUIREMENTS: usize = MAX_NODES * 4;
const MAX_NODE_NAME_BYTES: usize = 253;
// Long enough for a fully expanded IPv6 literal plus `/128`, while preventing
// hostile or malformed Node objects from retaining arbitrarily large strings
// in the long-lived projected cache.
const MAX_TOPOLOGY_VALUE_BYTES: usize = 64;
const MAX_ROUTE_LINES: usize = 4_096;
const MAX_ROUTE_FILE_BYTES: u64 = 1_048_576;
const MAX_DIAGNOSTIC_BYTES: usize = 512;
const REVALIDATE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
const VALIDATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
const WATCH_ERROR_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
/// A structural cluster bound cannot normally heal on transport-retry cadence.
/// Keep the proof failed closed while limiting every node-agent to four LISTs
/// per hour until the cluster shape changes.
const STRUCTURAL_RELIST_SECS: u64 = 20 * 60;

type NodeWatchStream =
    Pin<Box<dyn Stream<Item = Result<Event<Node>, kube_watcher::Error>> + Send + 'static>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressTopologyState {
    Disabled,
    Validating,
    Ready,
    Unavailable,
}

impl IngressTopologyState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Validating => "validating",
            Self::Ready => "ready",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressTopologyReason {
    Disabled,
    ValidationPending,
    Valid,
    ValidationTimeout,
    KubernetesUnavailable,
    NodeSetTooLarge,
    RequirementSetTooLarge,
    LocalNodeMissing,
    NodeTopologyIncomplete,
    NoRemoteTopologyEvidence,
    FamilyUnproved,
    DatapathUpdateFailed,
    TooManyInterfaces,
    InvalidInterfaceName,
    DeviceMissing,
    DeviceDown,
    Loopback,
    UnsupportedDevice,
    RouteTableUnavailable,
    RouteTableTooLarge,
    RouteTableInvalid,
    RouteMissing,
    RouteAmbiguous,
    UnsupportedTopology,
    WrongInterface,
    IncompleteInterfaceSet,
    UnexpectedInterface,
}

impl IngressTopologyReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ValidationPending => "validation_pending",
            Self::Valid => "valid",
            Self::ValidationTimeout => "validation_timeout",
            Self::KubernetesUnavailable => "kubernetes_unavailable",
            Self::NodeSetTooLarge => "node_set_too_large",
            Self::RequirementSetTooLarge => "requirement_set_too_large",
            Self::LocalNodeMissing => "local_node_missing",
            Self::NodeTopologyIncomplete => "node_topology_incomplete",
            Self::NoRemoteTopologyEvidence => "no_remote_topology_evidence",
            Self::FamilyUnproved => "family_unproved",
            Self::DatapathUpdateFailed => "datapath_update_failed",
            Self::TooManyInterfaces => "too_many_interfaces",
            Self::InvalidInterfaceName => "invalid_interface_name",
            Self::DeviceMissing => "device_missing",
            Self::DeviceDown => "device_down",
            Self::Loopback => "loopback",
            Self::UnsupportedDevice => "unsupported_device",
            Self::RouteTableUnavailable => "route_table_unavailable",
            Self::RouteTableTooLarge => "route_table_too_large",
            Self::RouteTableInvalid => "route_table_invalid",
            Self::RouteMissing => "route_missing",
            Self::RouteAmbiguous => "route_ambiguous",
            Self::UnsupportedTopology => "unsupported_topology",
            Self::WrongInterface => "wrong_interface",
            Self::IncompleteInterfaceSet => "incomplete_interface_set",
            Self::UnexpectedInterface => "unexpected_interface",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressTopologyStatus {
    pub state: IngressTopologyState,
    pub reason: IngressTopologyReason,
    pub configured_interfaces: u16,
    pub expected_interfaces: u16,
    pub ipv4_required: bool,
    pub ipv4_covered: bool,
    pub ipv6_required: bool,
    pub ipv6_covered: bool,
}

impl IngressTopologyStatus {
    pub const fn disabled() -> Self {
        Self {
            state: IngressTopologyState::Disabled,
            reason: IngressTopologyReason::Disabled,
            configured_interfaces: 0,
            expected_interfaces: 0,
            ipv4_required: false,
            ipv4_covered: false,
            ipv6_required: false,
            ipv6_covered: false,
        }
    }

    pub fn validating(configured_interfaces: usize) -> Self {
        Self {
            state: IngressTopologyState::Validating,
            reason: IngressTopologyReason::ValidationPending,
            configured_interfaces: saturating_count(configured_interfaces),
            expected_interfaces: 0,
            ipv4_required: false,
            ipv4_covered: false,
            ipv6_required: false,
            ipv6_covered: false,
        }
    }

    pub fn is_ready(self) -> bool {
        matches!(
            self.state,
            IngressTopologyState::Disabled | IngressTopologyState::Ready
        )
    }
}

impl Default for IngressTopologyStatus {
    fn default() -> Self {
        Self::disabled()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressTopologyOutcome {
    pub status: IngressTopologyStatus,
    pub diagnostic: String,
}

impl IngressTopologyOutcome {
    #[doc(hidden)]
    pub fn validation_timeout(
        configured_interfaces: usize,
        ipv4_required: bool,
        ipv6_required: bool,
    ) -> Self {
        unavailable(
            IngressTopologyReason::ValidationTimeout,
            configured_interfaces,
            0,
            ipv4_required,
            ipv6_required,
            "NodeWaypoint ingress topology validation exceeded its two-second budget",
        )
    }

    #[doc(hidden)]
    pub fn monitor_stopped(configured_interfaces: usize) -> Self {
        unavailable(
            IngressTopologyReason::KubernetesUnavailable,
            configured_interfaces,
            0,
            false,
            false,
            "the bounded Node topology monitor stopped unexpectedly",
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl IpCidr {
    pub fn parse(raw: &str) -> Result<Self, IngressTopologyReason> {
        let (address, prefix) = raw
            .split_once('/')
            .ok_or(IngressTopologyReason::NodeTopologyIncomplete)?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| IngressTopologyReason::NodeTopologyIncomplete)?;
        let prefix_len = prefix
            .parse::<u8>()
            .map_err(|_| IngressTopologyReason::NodeTopologyIncomplete)?;
        let max = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(IngressTopologyReason::NodeTopologyIncomplete);
        }
        Ok(Self {
            address: mask_ip(address, prefix_len),
            prefix_len,
        })
    }

    pub fn family(self) -> IpFamily {
        match self.address {
            IpAddr::V4(_) => IpFamily::Ipv4,
            IpAddr::V6(_) => IpFamily::Ipv6,
        }
    }

    fn contains_ip(self, address: IpAddr) -> bool {
        same_family(self.address, address) && mask_ip(address, self.prefix_len) == self.address
    }

    fn contains_cidr(self, other: Self) -> bool {
        self.prefix_len <= other.prefix_len && self.contains_ip(other.address)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub destination: IpCidr,
    pub interface: String,
    pub metric: u32,
    pub usable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkState {
    pub exists: bool,
    pub up: bool,
    pub loopback: bool,
    pub supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyRequirements {
    pub remote_pod_cidrs: Vec<IpCidr>,
    pub remote_node_addresses: Vec<IpAddr>,
    pub require_ipv4: bool,
    pub require_ipv6: bool,
}

#[derive(Debug, Clone)]
pub struct IngressTopologyValidator {
    configured_interfaces: Vec<String>,
    node_name: String,
    capture_supports_ipv6: bool,
    proc_root: PathBuf,
    sys_class_net: PathBuf,
}

impl IngressTopologyValidator {
    pub fn new(
        configured_interfaces: Vec<String>,
        node_name: impl Into<String>,
        capture_supports_ipv6: bool,
    ) -> Self {
        Self {
            configured_interfaces,
            node_name: node_name.into(),
            capture_supports_ipv6,
            proc_root: PathBuf::from("/proc"),
            sys_class_net: PathBuf::from("/sys/class/net"),
        }
    }

    #[doc(hidden)]
    pub fn with_roots(mut self, proc_root: PathBuf, sys_class_net: PathBuf) -> Self {
        self.proc_root = proc_root;
        self.sys_class_net = sys_class_net;
        self
    }

    pub fn configured_interfaces(&self) -> &[String] {
        &self.configured_interfaces
    }

    async fn validate_requirements(
        &self,
        requirements: TopologyRequirements,
    ) -> IngressTopologyOutcome {
        let ipv4_required = requirements.require_ipv4;
        let ipv6_required = requirements.require_ipv6;
        let configured = self.configured_interfaces.clone();
        let proc_root = self.proc_root.clone();
        let sys_class_net = self.sys_class_net.clone();
        match tokio::task::spawn_blocking(move || {
            validate_host_topology(&configured, &requirements, &proc_root, &sys_class_net)
        })
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => unavailable(
                IngressTopologyReason::RouteTableUnavailable,
                self.configured_interfaces.len(),
                0,
                ipv4_required,
                ipv6_required,
                "the bounded host-topology validation task did not complete",
            ),
        }
    }

    /// Start the bounded long-lived Node watch and host revalidation worker.
    ///
    /// The returned channel carries only completed outcomes, so neither Node
    /// API latency nor procfs/sysfs reads occupy the pod/CNI select loop. The
    /// worker owns at most `MAX_NODES` cached evidence projections, performs
    /// one initial paged LIST followed by a watch, and stops on shutdown.
    ///
    /// Authoritative cache-invalid outcomes (for example `NodeSetTooLarge`)
    /// withdraw readiness immediately and schedule a paced fresh LIST/watch
    /// snapshot. Incremental Apply/Delete events never repair an invalid cache.
    pub(crate) fn spawn_monitor(
        self,
        client: Client,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> IngressTopologyMonitor {
        let nodes: Api<Node> = Api::all(client);
        let watcher_config = kube_watcher::Config::default().page_size((MAX_NODES + 1) as u32);
        self.spawn_monitor_with_stream_factory(
            move || -> NodeWatchStream {
                Box::pin(kube_watcher::watcher(nodes.clone(), watcher_config.clone()))
            },
            shutdown_rx,
        )
    }

    /// Inject a Node event stream into the production monitor loop without a
    /// Kubernetes client. Kept crate-private and surfaced only through the
    /// existing external-test adapter.
    pub(crate) fn spawn_monitor_with_event_stream_for_test<S>(
        self,
        stream: S,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> IngressTopologyMonitor
    where
        S: Stream<Item = Result<Event<Node>, kube_watcher::Error>> + Send + 'static,
    {
        let mut stream = Some(stream);
        self.spawn_monitor_with_stream_factory(
            move || -> NodeWatchStream {
                match stream.take() {
                    Some(stream) => Box::pin(stream),
                    None => Box::pin(futures_util::stream::pending()),
                }
            },
            shutdown_rx,
        )
    }

    fn spawn_monitor_with_stream_factory<F>(
        self,
        mut stream_factory: F,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> IngressTopologyMonitor
    where
        F: FnMut() -> NodeWatchStream + Send + 'static,
    {
        let pending = IngressTopologyOutcome {
            status: IngressTopologyStatus::validating(self.configured_interfaces.len()),
            diagnostic: "NodeWaypoint ingress topology validation is pending".to_string(),
        };
        let (outcomes_tx, outcomes) = tokio::sync::watch::channel(pending);
        let task = tokio::spawn(async move {
            let mut recovery = NodeWatchCacheRecovery::new();
            let mut interval = tokio::time::interval(REVALIDATE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            let mut last_watch_error_log = None;
            let mut suppressed_watch_errors = 0_u64;

            'relist: loop {
                if *shutdown_rx.borrow() {
                    break;
                }
                let mut stream = stream_factory();
                let mut active_nodes = BTreeMap::<String, NodeTopologyEvidence>::new();
                let mut initializing: Option<BoundedNodeSet> = None;
                let mut requirements: Option<TopologyRequirements> = None;

                let watch_end = 'watch: loop {
                    if *shutdown_rx.borrow() {
                        break 'watch NodeWatchLoopEnd::Shutdown;
                    }
                    tokio::select! {
                        changed = shutdown_rx.changed() => {
                            if changed.is_err() || *shutdown_rx.borrow() {
                                break 'watch NodeWatchLoopEnd::Shutdown;
                            }
                        }
                        event = stream.next() => {
                            let Some(event) = event else {
                                let decision = recovery.on_stream_end();
                                publish_requirement_failure(
                                    &outcomes_tx,
                                    &self,
                                    IngressTopologyReason::KubernetesUnavailable,
                                );
                                match decision {
                                    NodeWatchCacheDecision::ForceRelist { backoff_secs } => {
                                        break 'watch NodeWatchLoopEnd::Relist { backoff_secs };
                                    }
                                    _ => continue,
                                }
                            };
                            match event {
                                Ok(Event::Init) => {
                                    // A relist is not a continuation of the last
                                    // authoritative snapshot. Withdraw any ready
                                    // outcome until InitDone publishes a complete,
                                    // bounded replacement.
                                    let _ = recovery.on_init();
                                    if requirements.take().is_some() {
                                        publish_requirement_failure(
                                            &outcomes_tx,
                                            &self,
                                            IngressTopologyReason::KubernetesUnavailable,
                                        );
                                    }
                                    initializing = Some(BoundedNodeSet::default());
                                }
                                Ok(Event::InitApply(node)) => {
                                    if let Some(nodes) = &mut initializing {
                                        nodes.insert(node);
                                    }
                                }
                                Ok(Event::InitDone) => {
                                    let Some(nodes) = initializing.take() else {
                                        let decision = recovery.on_missing_snapshot();
                                        requirements = None;
                                        active_nodes.clear();
                                        publish_requirement_failure(
                                            &outcomes_tx,
                                            &self,
                                            IngressTopologyReason::KubernetesUnavailable,
                                        );
                                        if let NodeWatchCacheDecision::ForceRelist {
                                            backoff_secs,
                                        } = decision
                                        {
                                            break 'watch NodeWatchLoopEnd::Relist {
                                                backoff_secs,
                                            };
                                        }
                                        continue;
                                    };
                                    if let Some(reason) = nodes.failure {
                                        let decision = recovery.on_invalid_snapshot(reason);
                                        requirements = None;
                                        active_nodes.clear();
                                        publish_requirement_failure(
                                            &outcomes_tx,
                                            &self,
                                            reason,
                                        );
                                        if let NodeWatchCacheDecision::ForceRelist {
                                            backoff_secs,
                                        } = decision
                                        {
                                            break 'watch NodeWatchLoopEnd::Relist {
                                                backoff_secs,
                                            };
                                        }
                                        continue;
                                    }
                                    let _ = recovery.on_valid_snapshot();
                                    active_nodes = nodes.nodes;
                                    requirements = derive_and_publish(
                                        &outcomes_tx,
                                        &self,
                                        active_nodes.values(),
                                        None,
                                    ).await;
                                }
                                Ok(Event::Apply(node)) => {
                                    if let NodeWatchCacheDecision::SuppressIncremental {
                                        reason,
                                    } = recovery.on_incremental()
                                    {
                                        publish_requirement_failure(
                                            &outcomes_tx,
                                            &self,
                                            reason,
                                        );
                                        continue;
                                    }
                                    match update_active_node(&mut active_nodes, node) {
                                        Ok(true) => {
                                            requirements = derive_and_publish(
                                                &outcomes_tx,
                                                &self,
                                                active_nodes.values(),
                                                requirements.as_ref(),
                                            ).await;
                                        }
                                        Ok(false) => {}
                                        Err(reason) => {
                                            let decision =
                                                recovery.on_incremental_invalid(reason);
                                            requirements = None;
                                            active_nodes.clear();
                                            publish_requirement_failure(
                                                &outcomes_tx,
                                                &self,
                                                reason,
                                            );
                                            if let NodeWatchCacheDecision::ForceRelist {
                                                backoff_secs,
                                            } = decision
                                            {
                                                break 'watch NodeWatchLoopEnd::Relist {
                                                    backoff_secs,
                                                };
                                            }
                                        }
                                    }
                                }
                                Ok(Event::Delete(node)) => {
                                    if let NodeWatchCacheDecision::SuppressIncremental {
                                        reason,
                                    } = recovery.on_incremental()
                                    {
                                        publish_requirement_failure(
                                            &outcomes_tx,
                                            &self,
                                            reason,
                                        );
                                        continue;
                                    }
                                    if let Some(name) = node.metadata.name {
                                        active_nodes.remove(&name);
                                        requirements = derive_and_publish(
                                            &outcomes_tx,
                                            &self,
                                            active_nodes.values(),
                                            requirements.as_ref(),
                                        ).await;
                                    } else {
                                        let reason =
                                            IngressTopologyReason::NodeTopologyIncomplete;
                                        let decision =
                                            recovery.on_incremental_invalid(reason);
                                        requirements = None;
                                        active_nodes.clear();
                                        publish_requirement_failure(
                                            &outcomes_tx,
                                            &self,
                                            reason,
                                        );
                                        if let NodeWatchCacheDecision::ForceRelist {
                                            backoff_secs,
                                        } = decision
                                        {
                                            break 'watch NodeWatchLoopEnd::Relist {
                                                backoff_secs,
                                            };
                                        }
                                    }
                                }
                                Err(error) => {
                                    // kube-runtime reconnects and relists, but stale
                                    // Kubernetes evidence must never keep readiness
                                    // true while that recovery is in progress.
                                    log_watch_error(
                                        &error,
                                        &mut last_watch_error_log,
                                        &mut suppressed_watch_errors,
                                    );
                                    let _ = recovery.on_watch_error();
                                    requirements = None;
                                    initializing = None;
                                    active_nodes.clear();
                                    publish_requirement_failure(
                                        &outcomes_tx,
                                        &self,
                                        IngressTopologyReason::KubernetesUnavailable,
                                    );
                                }
                            }
                        }
                        _ = interval.tick() => {
                            if let Some(current) = requirements.clone() {
                                let outcome = validate_with_timeout(&self, current).await;
                                outcomes_tx.send_replace(outcome);
                            }
                        }
                    }
                };

                match watch_end {
                    NodeWatchLoopEnd::Shutdown => break,
                    NodeWatchLoopEnd::Relist { backoff_secs } => {
                        let delay = crate::util::backoff::jittered_backoff(backoff_secs);
                        let sleep = tokio::time::sleep(delay);
                        tokio::pin!(sleep);
                        loop {
                            tokio::select! {
                                _ = &mut sleep => break,
                                changed = shutdown_rx.changed() => {
                                    if changed.is_err() || *shutdown_rx.borrow() {
                                        break 'relist;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        IngressTopologyMonitor { outcomes, task }
    }
}

enum NodeWatchLoopEnd {
    Shutdown,
    Relist { backoff_secs: u64 },
}

/// Pure controller for bounded Node-watch cache validity and paced recovery.
///
/// Ready topology may only be derived from a complete valid replacement
/// snapshot. Incremental Apply/Delete events never repair an invalid cache, and
/// repeated invalid snapshots advance a capped backoff instead of spinning.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeWatchCacheRecovery {
    invalid_reason: Option<IngressTopologyReason>,
    relist_backoff_secs: u64,
}

/// Decision emitted by [`NodeWatchCacheRecovery`] for the monitor loop / tests.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeWatchCacheDecision {
    /// Begin collecting a replacement Init snapshot; readiness stays withdrawn.
    StartInitializing,
    /// Commit a complete bounded snapshot; Ready may be derived from it.
    CommitSnapshot,
    /// Incremental mutation may update the active cache and re-derive.
    AllowIncremental,
    /// Keep publishing the invalid reason; never become Ready from this event.
    SuppressIncremental { reason: IngressTopologyReason },
    /// Authoritative cache is invalid; restart LIST/watch after the paced delay.
    ForceRelist { backoff_secs: u64 },
    /// Watch transport recovery is in progress; wait for kube-runtime Init.
    AwaitReconnect,
}

impl NodeWatchCacheRecovery {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            invalid_reason: None,
            relist_backoff_secs: crate::util::backoff::BACKOFF_INITIAL_SECS,
        }
    }

    #[doc(hidden)]
    pub fn invalid_reason(&self) -> Option<IngressTopologyReason> {
        self.invalid_reason
    }

    #[doc(hidden)]
    pub fn relist_backoff_secs(&self) -> u64 {
        self.relist_backoff_secs
    }

    #[doc(hidden)]
    pub fn on_init(&mut self) -> NodeWatchCacheDecision {
        self.invalid_reason = Some(IngressTopologyReason::KubernetesUnavailable);
        NodeWatchCacheDecision::StartInitializing
    }

    #[doc(hidden)]
    pub fn on_valid_snapshot(&mut self) -> NodeWatchCacheDecision {
        self.invalid_reason = None;
        self.relist_backoff_secs = crate::util::backoff::BACKOFF_INITIAL_SECS;
        NodeWatchCacheDecision::CommitSnapshot
    }

    #[doc(hidden)]
    pub fn on_invalid_snapshot(&mut self, reason: IngressTopologyReason) -> NodeWatchCacheDecision {
        self.invalid_reason = Some(reason);
        self.force_relist()
    }

    #[doc(hidden)]
    pub fn on_missing_snapshot(&mut self) -> NodeWatchCacheDecision {
        self.on_invalid_snapshot(IngressTopologyReason::KubernetesUnavailable)
    }

    #[doc(hidden)]
    pub fn on_incremental(&self) -> NodeWatchCacheDecision {
        if let Some(reason) = self.invalid_reason {
            NodeWatchCacheDecision::SuppressIncremental { reason }
        } else {
            NodeWatchCacheDecision::AllowIncremental
        }
    }

    #[doc(hidden)]
    pub fn on_incremental_invalid(
        &mut self,
        reason: IngressTopologyReason,
    ) -> NodeWatchCacheDecision {
        self.invalid_reason = Some(reason);
        self.force_relist()
    }

    #[doc(hidden)]
    pub fn on_watch_error(&mut self) -> NodeWatchCacheDecision {
        self.invalid_reason = Some(IngressTopologyReason::KubernetesUnavailable);
        NodeWatchCacheDecision::AwaitReconnect
    }

    /// A completed watcher stream cannot reconnect itself. Withdraw any
    /// previously valid snapshot and create a fresh LIST/watch generation
    /// after the same bounded recovery delay used for invalid snapshots.
    #[doc(hidden)]
    pub fn on_stream_end(&mut self) -> NodeWatchCacheDecision {
        self.invalid_reason = Some(IngressTopologyReason::KubernetesUnavailable);
        self.force_relist()
    }

    fn force_relist(&mut self) -> NodeWatchCacheDecision {
        if self.invalid_reason.is_some_and(structural_failure) {
            return NodeWatchCacheDecision::ForceRelist {
                backoff_secs: STRUCTURAL_RELIST_SECS,
            };
        }
        let backoff_secs = self.relist_backoff_secs;
        self.relist_backoff_secs =
            crate::util::backoff::next_backoff_secs(self.relist_backoff_secs, true);
        NodeWatchCacheDecision::ForceRelist { backoff_secs }
    }
}

pub(crate) struct IngressTopologyMonitor {
    pub(crate) outcomes: tokio::sync::watch::Receiver<IngressTopologyOutcome>,
    pub(crate) task: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct BoundedNodeSet {
    nodes: BTreeMap<String, NodeTopologyEvidence>,
    evidence_entries: usize,
    failure: Option<IngressTopologyReason>,
}

impl BoundedNodeSet {
    fn insert(&mut self, node: Node) {
        if self.failure.is_some() {
            return;
        }
        let evidence = match NodeTopologyEvidence::from_node(&node) {
            Ok(evidence) => evidence,
            Err(reason) => {
                self.failure = Some(reason);
                return;
            }
        };
        let name = evidence.name.clone();
        if !self.nodes.contains_key(&name) && self.nodes.len() >= MAX_NODES {
            self.failure = Some(IngressTopologyReason::NodeSetTooLarge);
            return;
        }
        let previous_entries = self
            .nodes
            .get(&name)
            .map_or(0, NodeTopologyEvidence::entry_count);
        let Some(evidence_entries) = self
            .evidence_entries
            .checked_sub(previous_entries)
            .and_then(|retained| retained.checked_add(evidence.entry_count()))
        else {
            self.failure = Some(IngressTopologyReason::RequirementSetTooLarge);
            return;
        };
        if evidence_entries > MAX_REQUIREMENTS {
            self.failure = Some(IngressTopologyReason::RequirementSetTooLarge);
            return;
        }
        self.evidence_entries = evidence_entries;
        self.nodes.insert(name, evidence);
    }
}

fn update_active_node(
    nodes: &mut BTreeMap<String, NodeTopologyEvidence>,
    node: Node,
) -> Result<bool, IngressTopologyReason> {
    let evidence = NodeTopologyEvidence::from_node(&node)?;
    let name = evidence.name.clone();
    if !nodes.contains_key(&name) && nodes.len() >= MAX_NODES {
        return Err(IngressTopologyReason::NodeSetTooLarge);
    }
    let current_entries = nodes.values().try_fold(0_usize, |total, node| {
        total
            .checked_add(node.entry_count())
            .ok_or(IngressTopologyReason::RequirementSetTooLarge)
    })?;
    let previous_entries = nodes
        .get(&name)
        .map_or(0, NodeTopologyEvidence::entry_count);
    let replacement_entries = current_entries
        .checked_sub(previous_entries)
        .and_then(|retained| retained.checked_add(evidence.entry_count()))
        .ok_or(IngressTopologyReason::RequirementSetTooLarge)?;
    if replacement_entries > MAX_REQUIREMENTS {
        return Err(IngressTopologyReason::RequirementSetTooLarge);
    }
    if nodes.get(&name) == Some(&evidence) {
        return Ok(false);
    }
    nodes.insert(name, evidence);
    Ok(true)
}

async fn derive_and_publish<'a>(
    outcomes: &tokio::sync::watch::Sender<IngressTopologyOutcome>,
    validator: &IngressTopologyValidator,
    nodes: impl Iterator<Item = &'a NodeTopologyEvidence>,
    previous: Option<&TopologyRequirements>,
) -> Option<TopologyRequirements> {
    match requirements_from_evidence(nodes, &validator.node_name, validator.capture_supports_ipv6) {
        Ok(requirements) => {
            // Node heartbeats generate frequent Apply events. The projected
            // evidence is cheap to rebuild, but procfs/sysfs validation is not:
            // only a changed route requirement needs an event-driven host pass.
            // The five-second interval remains the host-drift revalidation lane.
            if previous == Some(&requirements) {
                return Some(requirements);
            }
            let outcome = validate_with_timeout(validator, requirements.clone()).await;
            outcomes.send_replace(outcome);
            Some(requirements)
        }
        Err(reason) => {
            publish_requirement_failure(outcomes, validator, reason);
            None
        }
    }
}

async fn validate_with_timeout(
    validator: &IngressTopologyValidator,
    requirements: TopologyRequirements,
) -> IngressTopologyOutcome {
    let ipv4_required = requirements.require_ipv4;
    let ipv6_required = requirements.require_ipv6;
    match tokio::time::timeout(
        VALIDATION_TIMEOUT,
        validator.validate_requirements(requirements),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => IngressTopologyOutcome::validation_timeout(
            validator.configured_interfaces.len(),
            ipv4_required,
            ipv6_required,
        ),
    }
}

fn publish_requirement_failure(
    outcomes: &tokio::sync::watch::Sender<IngressTopologyOutcome>,
    validator: &IngressTopologyValidator,
    reason: IngressTopologyReason,
) {
    let diagnostic = match reason {
        IngressTopologyReason::KubernetesUnavailable => {
            "the long-lived Kubernetes Node topology watch is unavailable"
        }
        IngressTopologyReason::NodeSetTooLarge => {
            "the Kubernetes Node set exceeds the supported maximum of 256"
        }
        IngressTopologyReason::RequirementSetTooLarge => {
            "the aggregate Node PodCIDR/InternalIP requirement set exceeds its bounded limit"
        }
        IngressTopologyReason::LocalNodeMissing => {
            "the local Node is absent from the complete Kubernetes Node snapshot"
        }
        IngressTopologyReason::NoRemoteTopologyEvidence => {
            "no remote Node currently supplies an off-node route topology to prove"
        }
        IngressTopologyReason::FamilyUnproved => {
            "no observed remote PodCIDR family is supported by the configured capture listener"
        }
        _ => "Ready Kubernetes Nodes must publish supported PodCIDR and InternalIP evidence",
    };
    outcomes.send_replace(unavailable(
        reason,
        validator.configured_interfaces.len(),
        0,
        false,
        false,
        diagnostic,
    ));
}

pub fn validate_topology_snapshot(
    configured_interfaces: &[String],
    requirements: &TopologyRequirements,
    routes: &[RouteEntry],
    links: &BTreeMap<String, LinkState>,
) -> IngressTopologyOutcome {
    let configured_count = configured_interfaces.len();
    if configured_count > MAX_CONFIGURED_INTERFACES {
        return unavailable(
            IngressTopologyReason::TooManyInterfaces,
            configured_count,
            0,
            requirements.require_ipv4,
            requirements.require_ipv6,
            "configured ingress interface count exceeds the supported limit",
        );
    }
    let mut configured = BTreeSet::new();
    for interface in configured_interfaces {
        if !valid_interface_name(interface) {
            return unavailable(
                IngressTopologyReason::InvalidInterfaceName,
                configured_count,
                0,
                requirements.require_ipv4,
                requirements.require_ipv6,
                "a configured ingress interface name is invalid or unsafe",
            );
        }
        configured.insert(interface.clone());
        let Some(link) = links.get(interface) else {
            return unavailable(
                IngressTopologyReason::DeviceMissing,
                configured_count,
                0,
                requirements.require_ipv4,
                requirements.require_ipv6,
                "a configured ingress interface does not exist",
            );
        };
        let reason = if !link.exists {
            Some(IngressTopologyReason::DeviceMissing)
        } else if link.loopback {
            Some(IngressTopologyReason::Loopback)
        } else if !link.up {
            Some(IngressTopologyReason::DeviceDown)
        } else if !link.supported {
            Some(IngressTopologyReason::UnsupportedDevice)
        } else {
            None
        };
        if let Some(reason) = reason {
            return unavailable(
                reason,
                configured_count,
                0,
                requirements.require_ipv4,
                requirements.require_ipv6,
                reason_diagnostic(reason),
            );
        }
    }

    let mut expected = BTreeSet::new();
    let mut v4_covered = false;
    let mut v6_covered = false;
    for cidr in &requirements.remote_pod_cidrs {
        if (cidr.family() == IpFamily::Ipv4 && !requirements.require_ipv4)
            || (cidr.family() == IpFamily::Ipv6 && !requirements.require_ipv6)
        {
            continue;
        }
        let interface = match unique_route_interface(*cidr, routes) {
            Ok(interface) => interface,
            Err(reason) => {
                return unavailable(
                    reason,
                    configured_count,
                    expected.len(),
                    requirements.require_ipv4,
                    requirements.require_ipv6,
                    reason_diagnostic(reason),
                );
            }
        };
        expected.insert(interface.to_string());
        match cidr.family() {
            IpFamily::Ipv4 => v4_covered = true,
            IpFamily::Ipv6 => v6_covered = true,
        }
    }
    if expected.len() > MAX_CONFIGURED_INTERFACES {
        return unavailable(
            IngressTopologyReason::TooManyInterfaces,
            configured_count,
            expected.len(),
            requirements.require_ipv4,
            requirements.require_ipv6,
            "the route-derived ingress interface set exceeds the supported limit",
        );
    }

    // A supported topology has symmetric routing evidence: the remote node's
    // address and its pod CIDR resolve through the same proved ingress set. An
    // overlay/decapsulation shape that diverges here is intentionally refused;
    // Ferrum must not guess whether the outer or inner device owns the hook.
    for address in &requirements.remote_node_addresses {
        if (address.is_ipv4() && !requirements.require_ipv4)
            || (address.is_ipv6() && !requirements.require_ipv6)
        {
            continue;
        }
        let prefix_len = if address.is_ipv4() { 32 } else { 128 };
        let host = IpCidr {
            address: *address,
            prefix_len,
        };
        let interface = match unique_route_interface(host, routes) {
            Ok(interface) => interface,
            Err(reason) => {
                return unavailable(
                    reason,
                    configured_count,
                    expected.len(),
                    requirements.require_ipv4,
                    requirements.require_ipv6,
                    reason_diagnostic(reason),
                );
            }
        };
        if !expected.contains(interface) {
            return unavailable(
                IngressTopologyReason::UnsupportedTopology,
                configured_count,
                expected.len(),
                requirements.require_ipv4,
                requirements.require_ipv6,
                "remote-node and remote-PodCIDR routes diverge; this CNI topology is unsupported",
            );
        }
    }

    if (requirements.require_ipv4 && !v4_covered) || (requirements.require_ipv6 && !v6_covered) {
        return unavailable(
            IngressTopologyReason::FamilyUnproved,
            configured_count,
            expected.len(),
            requirements.require_ipv4,
            requirements.require_ipv6,
            "the complete remote-node route set could not be proved for every required family",
        );
    }
    for interface in &expected {
        match links.get(interface) {
            Some(link) if link.exists && link.up && !link.loopback && link.supported => {}
            Some(link) if link.loopback => {
                return unavailable(
                    IngressTopologyReason::Loopback,
                    configured_count,
                    expected.len(),
                    requirements.require_ipv4,
                    requirements.require_ipv6,
                    "a route-selected ingress interface is loopback",
                );
            }
            Some(link) if !link.up => {
                return unavailable(
                    IngressTopologyReason::DeviceDown,
                    configured_count,
                    expected.len(),
                    requirements.require_ipv4,
                    requirements.require_ipv6,
                    "a route-selected ingress interface is down",
                );
            }
            Some(_) => {
                return unavailable(
                    IngressTopologyReason::UnsupportedDevice,
                    configured_count,
                    expected.len(),
                    requirements.require_ipv4,
                    requirements.require_ipv6,
                    "a route-selected ingress interface has an unsupported link shape",
                );
            }
            None => {
                return unavailable(
                    IngressTopologyReason::DeviceMissing,
                    configured_count,
                    expected.len(),
                    requirements.require_ipv4,
                    requirements.require_ipv6,
                    "a route-selected ingress interface does not exist",
                );
            }
        }
    }

    let missing: Vec<_> = expected.difference(&configured).collect();
    let extra: Vec<_> = configured.difference(&expected).collect();
    if !missing.is_empty() || !extra.is_empty() {
        let (reason, diagnostic) = match (missing.is_empty(), extra.is_empty()) {
            (false, true) => (
                IngressTopologyReason::IncompleteInterfaceSet,
                "the configured ingress interface set omits a required node/CNI route device",
            ),
            (true, false) => (
                IngressTopologyReason::UnexpectedInterface,
                "the configured ingress interface set includes a device with no proved route role",
            ),
            (false, false) => (
                IngressTopologyReason::WrongInterface,
                "the configured ingress interface set does not match the proved node/CNI route set",
            ),
            (true, true) => (
                IngressTopologyReason::WrongInterface,
                "the configured ingress interface set could not be proved",
            ),
        };
        return unavailable(
            reason,
            configured_count,
            expected.len(),
            requirements.require_ipv4,
            requirements.require_ipv6,
            diagnostic,
        );
    }

    IngressTopologyOutcome {
        status: IngressTopologyStatus {
            state: IngressTopologyState::Ready,
            reason: IngressTopologyReason::Valid,
            configured_interfaces: saturating_count(configured_count),
            expected_interfaces: saturating_count(expected.len()),
            ipv4_required: requirements.require_ipv4,
            ipv4_covered: v4_covered,
            ipv6_required: requirements.require_ipv6,
            ipv6_covered: v6_covered,
        },
        diagnostic: bounded_diagnostic(
            "configured ingress interfaces exactly cover the proved node/CNI topology",
        ),
    }
}

#[doc(hidden)]
pub fn validate_host_topology_from_roots(
    configured_interfaces: &[String],
    requirements: &TopologyRequirements,
    proc_root: &Path,
    sys_class_net: &Path,
) -> IngressTopologyOutcome {
    let routes = match read_routes(
        proc_root,
        requirements.require_ipv4,
        requirements.require_ipv6,
    ) {
        Ok(routes) => routes,
        Err(reason) => {
            return unavailable(
                reason,
                configured_interfaces.len(),
                0,
                requirements.require_ipv4,
                requirements.require_ipv6,
                reason_diagnostic(reason),
            );
        }
    };
    let mut names: BTreeSet<String> = configured_interfaces.iter().cloned().collect();
    for route in &routes {
        names.insert(route.interface.clone());
    }
    let links = names
        .into_iter()
        .map(|name| {
            let state = read_link_state(sys_class_net, &name);
            (name, state)
        })
        .collect();
    validate_topology_snapshot(configured_interfaces, requirements, &routes, &links)
}

fn validate_host_topology(
    configured_interfaces: &[String],
    requirements: &TopologyRequirements,
    proc_root: &Path,
    sys_class_net: &Path,
) -> IngressTopologyOutcome {
    validate_host_topology_from_roots(
        configured_interfaces,
        requirements,
        proc_root,
        sys_class_net,
    )
}

#[doc(hidden)]
pub fn requirements_from_nodes(
    nodes: &[Node],
    local_node_name: &str,
    capture_supports_ipv6: bool,
) -> Result<TopologyRequirements, IngressTopologyReason> {
    if nodes.len() > MAX_NODES {
        return Err(IngressTopologyReason::NodeSetTooLarge);
    }
    let evidence = nodes
        .iter()
        .map(NodeTopologyEvidence::from_node)
        .collect::<Result<Vec<_>, _>>()?;
    requirements_from_evidence(evidence.iter(), local_node_name, capture_supports_ipv6)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeTopologyEvidence {
    name: String,
    ready: bool,
    pod_cidrs: Vec<String>,
    internal_ips: Vec<String>,
}

impl NodeTopologyEvidence {
    fn entry_count(&self) -> usize {
        self.pod_cidrs.len().saturating_add(self.internal_ips.len())
    }

    fn from_node(node: &Node) -> Result<Self, IngressTopologyReason> {
        let name = node
            .metadata
            .name
            .as_deref()
            .ok_or(IngressTopologyReason::NodeTopologyIncomplete)?;
        if name.len() > MAX_NODE_NAME_BYTES {
            return Err(IngressTopologyReason::RequirementSetTooLarge);
        }
        let name = name.to_string();
        let ready = node
            .status
            .as_ref()
            .and_then(|status| status.conditions.as_ref())
            .and_then(|conditions| {
                conditions
                    .iter()
                    .find(|condition| condition.type_ == "Ready")
            })
            .is_some_and(|condition| condition.status == "True");
        let mut pod_cidrs = Vec::new();
        if let Some(spec) = node.spec.as_ref() {
            if let Some(cidrs) = spec.pod_cidrs.as_ref() {
                for cidr in cidrs.iter().take(MAX_REQUIREMENTS + 1) {
                    if cidr.len() > MAX_TOPOLOGY_VALUE_BYTES {
                        return Err(IngressTopologyReason::RequirementSetTooLarge);
                    }
                    pod_cidrs.push(cidr.clone());
                }
            } else if let Some(cidr) = spec.pod_cidr.as_ref() {
                if cidr.len() > MAX_TOPOLOGY_VALUE_BYTES {
                    return Err(IngressTopologyReason::RequirementSetTooLarge);
                }
                pod_cidrs.push(cidr.clone());
            }
        }
        if pod_cidrs.len() > MAX_REQUIREMENTS {
            return Err(IngressTopologyReason::RequirementSetTooLarge);
        }
        let mut internal_ips = Vec::new();
        for address in node
            .status
            .as_ref()
            .and_then(|status| status.addresses.as_ref())
            .into_iter()
            .flatten()
            .filter(|address| address.type_ == "InternalIP")
            .take(MAX_REQUIREMENTS + 1)
        {
            if address.address.len() > MAX_TOPOLOGY_VALUE_BYTES {
                return Err(IngressTopologyReason::RequirementSetTooLarge);
            }
            internal_ips.push(address.address.clone());
        }
        if internal_ips.len() > MAX_REQUIREMENTS {
            return Err(IngressTopologyReason::RequirementSetTooLarge);
        }
        Ok(Self {
            name,
            ready,
            pod_cidrs,
            internal_ips,
        })
    }
}

pub(crate) fn apply_bounded_node_topology_sequence_for_test(
    snapshot: Vec<Node>,
    incremental: Option<Node>,
) -> Result<(usize, usize), IngressTopologyReason> {
    let mut bounded = BoundedNodeSet::default();
    for node in snapshot {
        bounded.insert(node);
    }
    if let Some(reason) = bounded.failure {
        return Err(reason);
    }
    if let Some(node) = incremental {
        update_active_node(&mut bounded.nodes, node)?;
    }
    let evidence_entries = bounded.nodes.values().try_fold(0_usize, |total, node| {
        total
            .checked_add(node.entry_count())
            .ok_or(IngressTopologyReason::RequirementSetTooLarge)
    })?;
    Ok((bounded.nodes.len(), evidence_entries))
}

fn requirements_from_evidence<'a>(
    nodes: impl Iterator<Item = &'a NodeTopologyEvidence>,
    local_node_name: &str,
    capture_supports_ipv6: bool,
) -> Result<TopologyRequirements, IngressTopologyReason> {
    let mut local_found = false;
    let mut remote_pod_cidrs = Vec::new();
    let mut remote_node_addresses = Vec::new();
    let mut observed_ipv4 = false;
    let mut observed_ipv6 = false;
    let mut remote_evidence_found = false;
    for node in nodes {
        if node.name == local_node_name {
            local_found = true;
            continue;
        }
        if node.pod_cidrs.is_empty() {
            if node.ready {
                return Err(IngressTopologyReason::NodeTopologyIncomplete);
            }
            continue;
        }
        let mut node_cidrs = Vec::new();
        let mut node_cidr_invalid = false;
        let mut node_observed_ipv6 = false;
        for raw_cidr in &node.pod_cidrs {
            let cidr = match IpCidr::parse(raw_cidr) {
                Ok(cidr) => cidr,
                Err(reason) if node.ready => return Err(reason),
                Err(_) => {
                    node_cidr_invalid = true;
                    break;
                }
            };
            node_observed_ipv6 |= cidr.family() == IpFamily::Ipv6;
            if (cidr.family() == IpFamily::Ipv4 || capture_supports_ipv6)
                && !remote_pod_cidrs.contains(&cidr)
            {
                let total = remote_pod_cidrs.len() + remote_node_addresses.len() + node_cidrs.len();
                push_unique_bounded(&mut node_cidrs, cidr, total)?;
            }
        }
        if node_cidr_invalid {
            continue;
        }
        let node_requires_ipv4 = node_cidrs
            .iter()
            .any(|cidr| cidr.family() == IpFamily::Ipv4);
        let node_requires_ipv6 = node_cidrs
            .iter()
            .any(|cidr| cidr.family() == IpFamily::Ipv6);
        let mut node_addresses = Vec::new();
        for raw_address in &node.internal_ips {
            let Ok(address) = raw_address.parse::<IpAddr>() else {
                continue;
            };
            if !usable_internal_ip(address) {
                continue;
            }
            let required_family = (address.is_ipv4() && node_requires_ipv4)
                || (address.is_ipv6() && node_requires_ipv6);
            if required_family && !remote_node_addresses.contains(&address) {
                let total = remote_pod_cidrs.len()
                    + remote_node_addresses.len()
                    + node_cidrs.len()
                    + node_addresses.len();
                push_unique_bounded(&mut node_addresses, address, total)?;
            }
        }
        if (node_requires_ipv4 && !node_addresses.iter().any(IpAddr::is_ipv4))
            || (node_requires_ipv6 && !node_addresses.iter().any(IpAddr::is_ipv6))
        {
            if node.ready {
                return Err(IngressTopologyReason::NodeTopologyIncomplete);
            }
            continue;
        }
        observed_ipv4 |= node_requires_ipv4;
        observed_ipv6 |= node_observed_ipv6;
        remote_evidence_found = true;
        for cidr in node_cidrs {
            let total = remote_pod_cidrs.len() + remote_node_addresses.len();
            push_unique_bounded(&mut remote_pod_cidrs, cidr, total)?;
        }
        for address in node_addresses {
            let total = remote_pod_cidrs.len() + remote_node_addresses.len();
            push_unique_bounded(&mut remote_node_addresses, address, total)?;
        }
    }
    if !local_found {
        return Err(IngressTopologyReason::LocalNodeMissing);
    }
    if !remote_evidence_found {
        return Err(IngressTopologyReason::NoRemoteTopologyEvidence);
    }
    let require_ipv4 = observed_ipv4;
    let require_ipv6 = observed_ipv6 && capture_supports_ipv6;
    if !require_ipv4 && !require_ipv6 {
        return Err(IngressTopologyReason::FamilyUnproved);
    }
    remote_pod_cidrs.sort_by_key(|cidr| (cidr.address, cidr.prefix_len));
    remote_node_addresses.sort_unstable();
    Ok(TopologyRequirements {
        remote_pod_cidrs,
        remote_node_addresses,
        require_ipv4,
        require_ipv6,
    })
}

fn push_unique_bounded<T: PartialEq>(
    requirements: &mut Vec<T>,
    value: T,
    current_total: usize,
) -> Result<(), IngressTopologyReason> {
    if requirements.contains(&value) {
        return Ok(());
    }
    if current_total >= MAX_REQUIREMENTS {
        return Err(IngressTopologyReason::RequirementSetTooLarge);
    }
    requirements.push(value);
    Ok(())
}

fn usable_internal_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !address.is_link_local()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
        }
    }
}

fn unique_route_interface(
    requirement: IpCidr,
    routes: &[RouteEntry],
) -> Result<&str, IngressTopologyReason> {
    let mut covering: Vec<&RouteEntry> = routes
        .iter()
        .filter(|route| route.usable && route.destination.contains_cidr(requirement))
        .collect();
    if covering.is_empty() {
        return Err(IngressTopologyReason::RouteMissing);
    }
    let best_prefix = covering
        .iter()
        .map(|route| route.destination.prefix_len)
        .max()
        .ok_or(IngressTopologyReason::RouteMissing)?;
    covering.retain(|route| route.destination.prefix_len == best_prefix);
    let best_metric = covering
        .iter()
        .map(|route| route.metric)
        .min()
        .ok_or(IngressTopologyReason::RouteMissing)?;
    covering.retain(|route| route.metric == best_metric);
    let candidates: BTreeSet<&str> = covering
        .iter()
        .map(|route| route.interface.as_str())
        .collect();
    if candidates.len() != 1 {
        return Err(IngressTopologyReason::RouteAmbiguous);
    }
    let interface = candidates
        .iter()
        .next()
        .copied()
        .ok_or(IngressTopologyReason::RouteMissing)?;

    // An active reject route at the selected prefix, or a more-specific reject
    // inside the requirement, disproves complete coverage even though a broad
    // usable route also exists. Ignore only broader rejects shadowed by the
    // selected usable route.
    if routes.iter().any(|route| {
        !route.usable
            && route.destination.family() == requirement.family()
            && ((route.destination.prefix_len >= best_prefix
                && route.destination.contains_cidr(requirement))
                || (route.destination.prefix_len > best_prefix
                    && requirement.contains_cidr(route.destination)))
    }) {
        return Err(IngressTopologyReason::RouteAmbiguous);
    }

    // A more-specific route inside a PodCIDR means one representative address
    // cannot prove the whole prefix. Require every such split to stay on the
    // same device; otherwise the configured set would be incomplete/ambiguous.
    for route in routes {
        if !route.usable
            || route.destination.family() != requirement.family()
            || route.destination.prefix_len <= best_prefix
            || !requirement.contains_ip(route.destination.address)
        {
            continue;
        }
        if route.interface != interface {
            return Err(IngressTopologyReason::RouteAmbiguous);
        }
    }
    Ok(interface)
}

fn read_routes(
    proc_root: &Path,
    require_ipv4: bool,
    require_ipv6: bool,
) -> Result<Vec<RouteEntry>, IngressTopologyReason> {
    let mut routes = Vec::new();
    if require_ipv4 {
        routes.extend(parse_ipv4_routes(&read_bounded(
            &proc_root.join("net/route"),
        )?)?);
    }
    if require_ipv6 {
        routes.extend(parse_ipv6_routes(&read_bounded(
            &proc_root.join("net/ipv6_route"),
        )?)?);
    }
    Ok(routes)
}

fn read_bounded(path: &Path) -> Result<String, IngressTopologyReason> {
    let metadata =
        std::fs::metadata(path).map_err(|_| IngressTopologyReason::RouteTableUnavailable)?;
    if metadata.len() > MAX_ROUTE_FILE_BYTES {
        return Err(IngressTopologyReason::RouteTableTooLarge);
    }
    let file =
        std::fs::File::open(path).map_err(|_| IngressTopologyReason::RouteTableUnavailable)?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len().min(MAX_ROUTE_FILE_BYTES)).unwrap_or_default(),
    );
    file.take(MAX_ROUTE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| IngressTopologyReason::RouteTableUnavailable)?;
    if bytes.len() as u64 > MAX_ROUTE_FILE_BYTES {
        return Err(IngressTopologyReason::RouteTableTooLarge);
    }
    let contents =
        String::from_utf8(bytes).map_err(|_| IngressTopologyReason::RouteTableInvalid)?;
    if contents.lines().count() > MAX_ROUTE_LINES {
        return Err(IngressTopologyReason::RouteTableTooLarge);
    }
    Ok(contents)
}

#[doc(hidden)]
pub fn parse_ipv4_route_file(contents: &str) -> Result<Vec<RouteEntry>, IngressTopologyReason> {
    parse_ipv4_routes(contents)
}

fn parse_ipv4_routes(contents: &str) -> Result<Vec<RouteEntry>, IngressTopologyReason> {
    let mut routes = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        if index == 0 && line.starts_with("Iface") {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        if fields.len() < 8 {
            return Err(IngressTopologyReason::RouteTableInvalid);
        }
        let flags = u32::from_str_radix(fields[3], 16)
            .map_err(|_| IngressTopologyReason::RouteTableInvalid)?;
        if flags & 0x1 == 0 {
            continue;
        }
        let usable = flags & 0x200 == 0;
        if usable && !valid_interface_name(fields[0]) {
            return Err(IngressTopologyReason::RouteTableInvalid);
        }
        let destination = ipv4_from_proc_hex(fields[1])?;
        let mask = ipv4_from_proc_hex(fields[7])?;
        let mask_u32 = u32::from(mask);
        if mask_u32.leading_ones() + mask_u32.trailing_zeros() != 32 {
            return Err(IngressTopologyReason::RouteTableInvalid);
        }
        let metric = fields[6]
            .parse::<u32>()
            .map_err(|_| IngressTopologyReason::RouteTableInvalid)?;
        routes.push(RouteEntry {
            destination: IpCidr {
                address: IpAddr::V4(Ipv4Addr::from(u32::from(destination) & mask_u32)),
                prefix_len: mask_u32.leading_ones() as u8,
            },
            interface: fields[0].to_string(),
            metric,
            usable,
        });
    }
    Ok(routes)
}

#[doc(hidden)]
pub fn parse_ipv6_route_file(contents: &str) -> Result<Vec<RouteEntry>, IngressTopologyReason> {
    parse_ipv6_routes(contents)
}

fn parse_ipv6_routes(contents: &str) -> Result<Vec<RouteEntry>, IngressTopologyReason> {
    let mut routes = Vec::new();
    for line in contents.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        if fields.len() < 10 {
            return Err(IngressTopologyReason::RouteTableInvalid);
        }
        let flags = u32::from_str_radix(fields[8], 16)
            .map_err(|_| IngressTopologyReason::RouteTableInvalid)?;
        if flags & 0x1 == 0 {
            continue;
        }
        let source_prefix_len = u8::from_str_radix(fields[3], 16)
            .map_err(|_| IngressTopologyReason::RouteTableInvalid)?;
        if source_prefix_len > 128 {
            return Err(IngressTopologyReason::RouteTableInvalid);
        }
        // Source-specific and reject routes cannot prove generic symmetric
        // reachability for every packet in a remote PodCIDR. Retain them as
        // negative evidence so a relevant equal/more-specific entry makes the
        // topology ambiguous instead of being silently ignored.
        let usable = flags & 0x200 == 0 && source_prefix_len == 0;
        if usable && !valid_interface_name(fields[9]) {
            return Err(IngressTopologyReason::RouteTableInvalid);
        }
        let address = ipv6_from_hex(fields[0])?;
        let prefix_len = u8::from_str_radix(fields[1], 16)
            .map_err(|_| IngressTopologyReason::RouteTableInvalid)?;
        if prefix_len > 128 {
            return Err(IngressTopologyReason::RouteTableInvalid);
        }
        let metric = u32::from_str_radix(fields[5], 16)
            .map_err(|_| IngressTopologyReason::RouteTableInvalid)?;
        routes.push(RouteEntry {
            destination: IpCidr {
                address: mask_ip(IpAddr::V6(address), prefix_len),
                prefix_len,
            },
            interface: fields[9].to_string(),
            metric,
            usable,
        });
    }
    Ok(routes)
}

#[doc(hidden)]
pub fn read_link_state_from_root(sys_class_net: &Path, interface: &str) -> LinkState {
    if !valid_interface_name(interface) {
        return LinkState {
            exists: false,
            up: false,
            loopback: false,
            supported: false,
        };
    }
    let root = sys_class_net.join(interface);
    if !root.is_dir() {
        return LinkState {
            exists: false,
            up: false,
            loopback: false,
            supported: false,
        };
    }
    let flags = read_trimmed(&root.join("flags"))
        .and_then(|raw| u32::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    let operstate = read_trimmed(&root.join("operstate")).unwrap_or_default();
    let carrier_up = read_trimmed(&root.join("carrier")).is_some_and(|value| value == "1");
    let link_type = read_trimmed(&root.join("type"))
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let loopback = flags & 0x8 != 0 || link_type == 772 || interface == "lo";
    let bridge = root.join("bridge").exists();
    let tunnel = root.join("tun_flags").exists();
    let bond = root.join("bonding").exists();
    let physical = root.join("device").exists();
    let ifindex = read_trimmed(&root.join("ifindex")).and_then(|value| value.parse::<u32>().ok());
    let iflink = read_trimmed(&root.join("iflink")).and_then(|value| value.parse::<u32>().ok());
    // Physical NICs have a device symlink. Peer-backed virtual L3 devices
    // (notably the veth presented as eth0 inside kind nodes) have distinct
    // ifindex/iflink values. Reject self-linked virtual devices such as dummy
    // links, along with explicit bridge/tun/bond shapes, because sysfs alone
    // cannot prove them to be a supported remote-node ingress attachment.
    let physical_or_peer_l3 = physical || matches!((ifindex, iflink), (Some(a), Some(b)) if a != b);
    LinkState {
        exists: true,
        up: flags & 0x1 != 0 && operstate == "up" && carrier_up,
        loopback,
        supported: link_type == 1 && !bridge && !tunnel && !bond && physical_or_peer_l3,
    }
}

fn read_link_state(sys_class_net: &Path, interface: &str) -> LinkState {
    read_link_state_from_root(sys_class_net, interface)
}

fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
}

fn ipv4_from_proc_hex(raw: &str) -> Result<Ipv4Addr, IngressTopologyReason> {
    let value =
        u32::from_str_radix(raw, 16).map_err(|_| IngressTopologyReason::RouteTableInvalid)?;
    Ok(Ipv4Addr::from(value.to_le_bytes()))
}

fn ipv6_from_hex(raw: &str) -> Result<Ipv6Addr, IngressTopologyReason> {
    let raw = raw.as_bytes();
    if raw.len() != 32 || !raw.is_ascii() {
        return Err(IngressTopologyReason::RouteTableInvalid);
    }
    let mut bytes = [0u8; 16];
    for (byte, pair) in bytes.iter_mut().zip(raw.chunks_exact(2)) {
        let high = hex_nibble(pair[0]).ok_or(IngressTopologyReason::RouteTableInvalid)?;
        let low = hex_nibble(pair[1]).ok_or(IngressTopologyReason::RouteTableInvalid)?;
        *byte = (high << 4) | low;
    }
    Ok(Ipv6Addr::from(bytes))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn valid_interface_name(interface: &str) -> bool {
    !interface.is_empty()
        && interface != "."
        && interface != ".."
        && interface.len() <= 15
        && interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn structural_failure(reason: IngressTopologyReason) -> bool {
    matches!(
        reason,
        IngressTopologyReason::NodeSetTooLarge | IngressTopologyReason::RequirementSetTooLarge
    )
}

fn log_watch_error(
    error: &kube_watcher::Error,
    last_log: &mut Option<std::time::Instant>,
    suppressed: &mut u64,
) {
    let now = std::time::Instant::now();
    if last_log.is_some_and(|last| now.duration_since(last) < WATCH_ERROR_LOG_INTERVAL) {
        *suppressed = suppressed.saturating_add(1);
        return;
    }
    let (stage, class, status_code) = classify_watch_error(error);
    tracing::warn!(
        stage,
        class,
        status_code,
        suppressed_since_last = *suppressed,
        "Kubernetes Node topology watch failed; readiness remains withdrawn while kube-rs retries"
    );
    *last_log = Some(now);
    *suppressed = 0;
}

fn classify_watch_error(error: &kube_watcher::Error) -> (&'static str, &'static str, u16) {
    match error {
        kube_watcher::Error::InitialListFailed(error) => {
            let (class, code) = classify_client_error(error);
            ("initial_list", class, code)
        }
        kube_watcher::Error::WatchStartFailed(error) => {
            let (class, code) = classify_client_error(error);
            ("watch_start", class, code)
        }
        kube_watcher::Error::WatchError(status) => (
            "watch_event",
            classify_status_code(status.code),
            status.code,
        ),
        kube_watcher::Error::WatchFailed(error) => {
            let (class, code) = classify_client_error(error);
            ("watch_stream", class, code)
        }
        kube_watcher::Error::NoResourceVersion => ("resource_version", "protocol", 0),
    }
}

fn classify_client_error(error: &kube::Error) -> (&'static str, u16) {
    match error {
        kube::Error::Api(status) => (classify_status_code(status.code), status.code),
        _ => ("transport", 0),
    }
}

fn classify_status_code(code: u16) -> &'static str {
    match code {
        401 | 403 => "authorization",
        404 | 405 => "api_contract",
        408 | 429 | 500..=599 => "transient_api",
        _ => "api_error",
    }
}

fn mask_ip(address: IpAddr, prefix_len: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
        }
        IpAddr::V6(address) => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_len)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
        }
    }
}

fn same_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn unavailable(
    reason: IngressTopologyReason,
    configured_interfaces: usize,
    expected_interfaces: usize,
    ipv4_required: bool,
    ipv6_required: bool,
    diagnostic: &str,
) -> IngressTopologyOutcome {
    IngressTopologyOutcome {
        status: IngressTopologyStatus {
            state: IngressTopologyState::Unavailable,
            reason,
            configured_interfaces: saturating_count(configured_interfaces),
            expected_interfaces: saturating_count(expected_interfaces),
            ipv4_required,
            ipv4_covered: false,
            ipv6_required,
            ipv6_covered: false,
        },
        diagnostic: bounded_diagnostic(diagnostic),
    }
}

fn reason_diagnostic(reason: IngressTopologyReason) -> &'static str {
    match reason {
        IngressTopologyReason::DeviceMissing => "a required ingress interface does not exist",
        IngressTopologyReason::DeviceDown => "a required ingress interface is down",
        IngressTopologyReason::Loopback => {
            "loopback cannot carry supported remote-node pod traffic"
        }
        IngressTopologyReason::UnsupportedDevice => {
            "the device link shape is not supported by the routed NodeWaypoint topology"
        }
        IngressTopologyReason::RouteTableUnavailable => "the host route table is unavailable",
        IngressTopologyReason::RouteTableTooLarge => {
            "the host route table exceeds the validation bound"
        }
        IngressTopologyReason::RouteTableInvalid => {
            "the host route table is malformed or unsupported"
        }
        IngressTopologyReason::RouteMissing => {
            "a required remote-node route has no usable host route"
        }
        IngressTopologyReason::RouteAmbiguous => {
            "multiple or split route devices make the ingress attach point ambiguous"
        }
        _ => "the NodeWaypoint ingress interface topology could not be proved",
    }
}

fn bounded_diagnostic(diagnostic: &str) -> String {
    diagnostic.chars().take(MAX_DIAGNOSTIC_BYTES).collect()
}

fn saturating_count(count: usize) -> u16 {
    u16::try_from(count).unwrap_or(u16::MAX)
}
