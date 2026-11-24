//! Exact destination routing for shared NodeWaypoint UDP listeners (issue #3861).
//!
//! A NodeWaypoint is `hostNetwork: true`, so it can bind a given UDP port
//! exactly once on the node. Two Kubernetes Services that declare the same UDP
//! port (separate DNS, syslog, telemetry, game or custom-protocol Services in
//! different namespaces) are routine and valid, and the datapath already
//! preserves the discriminator that tells them apart: the Service-path steering
//! rules perform **no** rewrite, so a steered datagram arrives with the original
//! ClusterIP as its local destination and `IP_PKTINFO` / `IPV6_PKTINFO` reports
//! it verbatim.
//!
//! This module turns that kernel fact into an exact route table. One shared
//! datagram listener owns the port; every datagram selects exactly one Service
//! route by canonical `(local destination IP, listen port)` **before** any
//! session lookup, plugin hook, backend selection or accounting runs. The port
//! half of that key is the listener's own bound port, which every datagram this
//! socket receives carries by construction. There is no fallback: an absent or
//! unrecognized local destination is refused before a session slot, pending
//! gate, or backend socket exists.
//!
//! Load-bearing invariants:
//!
//! * **Exactness.** Routes are keyed by a canonicalized `IpAddr` (IPv4-mapped
//!   IPv6 is folded onto its IPv4 form, so a dual-stack `[::]` bind and a
//!   dedicated v4 bind agree). A duplicate exact claim is refused for **every**
//!   ambiguous claimant at materialization, so the table can never hold an
//!   order-dependent winner.
//! * **No inference.** A route is never derived from the numeric port alone.
//!   A Service with no ClusterIP (headless) publishes no destination and is
//!   reachable only over the documented direct-node-address boundary, which
//!   requires the port to have exactly one claimant.
//! * **Lock-free reads.** The table is an immutable snapshot behind an
//!   `ArcSwap`. Adding or removing a Service republishes a complete new table
//!   without restarting the listener, so a second claimant entering the slice
//!   never withdraws the first one's socket.
//! * **Owner identity.** Each route stores its `NamespacedResourceId` as an
//!   `Arc` so the receive path can clone that exact namespaced owner into the
//!   UDP session key without allocating. A destination that changes owner is a
//!   different session; an equivalent republication of the same owner remains
//!   equal. The destination-table generation is not the session identity.
//! * **Bounded diagnostics.** Refusals are a closed `&'static str` enum with
//!   rate-limited warns. Service names never become metric labels.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::warn;

use crate::config::db_backend::NamespacedResourceId;

/// Fold an IPv4-mapped IPv6 address onto its IPv4 form.
///
/// A dual-stack `[::]` listener reports an IPv4 datagram's local destination as
/// `::ffff:a.b.c.d`, while the Service inventory publishes `a.b.c.d`. Without
/// this both spellings would be distinct keys and every steered IPv4 datagram
/// would be refused as unknown on a dual-stack bind.
#[inline]
pub fn canonical_destination_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

/// Whether an address is usable as an exact Service destination.
///
/// Unspecified, loopback, multicast and broadcast addresses are refused: none
/// of them can identify one Service, and admitting them would let a route claim
/// traffic addressed to the node itself.
#[inline]
pub fn destination_ip_is_admissible(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_loopback()
                && !v4.is_multicast()
                && v4 != Ipv4Addr::BROADCAST
        }
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_loopback() && !v6.is_multicast(),
    }
}

/// One exact destination route: the Service address a steered workload
/// addressed, and the generated listener proxy that exclusively owns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeWaypointUdpDestinationRoute {
    /// Canonical local destination address (see [`canonical_destination_ip`]).
    pub destination: IpAddr,
    /// Listen port this route is served on. Part of the exact key.
    pub listen_port: u16,
    /// The generated `__mesh-nw-udp-*` listener proxy that owns this
    /// destination — its upstream, policy scope, plugin decisions, accounting
    /// and reply source. Never inferred from the port.
    ///
    /// Stored as `Arc` so the receive hot path can clone this exact
    /// namespaced identity into `UdpSessionKey` without allocating or
    /// cloning namespace/id Strings per datagram. Hash/equality of the
    /// session key compare the inner `(namespace, id)`, not this pointer.
    ///
    /// The frontend posture (plain UDP or terminating DTLS) is not carried
    /// here: one bound socket speaks one protocol, so mesh materialization
    /// refuses every claimant of a port whose services disagree on it
    /// (`mixed_frontend_posture`) before any route is built.
    pub proxy: Arc<NamespacedResourceId>,
}

impl NodeWaypointUdpDestinationRoute {
    /// Build a route whose owner identity is already `Arc`-backed for the
    /// receive hot path.
    pub fn new(destination: IpAddr, listen_port: u16, proxy: NamespacedResourceId) -> Self {
        Self {
            destination: canonical_destination_ip(destination),
            listen_port,
            proxy: Arc::new(proxy),
        }
    }

    /// Clone the precomputed owner identity for session-key construction.
    #[inline]
    pub fn owner_arc(&self) -> Arc<NamespacedResourceId> {
        Arc::clone(&self.proxy)
    }
}

/// Why a datagram could not be attributed to an exact destination route.
///
/// A closed set of `&'static str` values: these reach logs and counters, and a
/// registry- or peer-supplied value must never become a label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeWaypointUdpDestinationRefusal {
    /// The kernel reported no local destination for this datagram. On a scoped
    /// listener `IP_PKTINFO` is a startup precondition, so this means the cmsg
    /// was absent for this datagram specifically.
    MissingLocalDestination,
    /// The local destination is not an exact route on this listener.
    UnknownDestination,
    /// The listener currently owns no routes (withdrawn generation).
    NoRoutes,
    /// The destination still exists, but a different namespaced Service now
    /// owns it. An established session admitted for the previous owner must
    /// stop before either direction can emit another datagram.
    OwnerChanged,
}

impl NodeWaypointUdpDestinationRefusal {
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingLocalDestination => "missing_local_destination",
            Self::UnknownDestination => "unknown_destination",
            Self::NoRoutes => "no_routes",
            Self::OwnerChanged => "owner_changed",
        }
    }
}

/// One immutable accepted generation of a listener's exact destination table.
#[derive(Debug)]
pub struct NodeWaypointUdpDestinationTable {
    generation: u64,
    #[allow(dead_code)] // External unit tests / diagnostics; the router owns the hot-path port.
    listen_port: u16,
    routes: HashMap<IpAddr, Arc<NodeWaypointUdpDestinationRoute>>,
}

impl NodeWaypointUdpDestinationTable {
    #[inline]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[inline]
    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Sorted owning proxy identities, for diagnostics and tests.
    pub fn owners(&self) -> Vec<NamespacedResourceId> {
        let mut owners: Vec<NamespacedResourceId> = self
            .routes
            .values()
            .map(|route| route.proxy.as_ref().clone())
            .collect();
        owners.sort_by(|a, b| (&a.namespace, &a.id).cmp(&(&b.namespace, &b.id)));
        owners.dedup_by(|a, b| a == b);
        owners
    }

    /// Sorted canonical destinations, for diagnostics and tests.
    pub fn destinations(&self) -> Vec<IpAddr> {
        let mut destinations: Vec<IpAddr> = self.routes.keys().copied().collect();
        destinations.sort();
        destinations
    }
}

/// Lock-free destination router for one shared NodeWaypoint UDP listener.
///
/// The receive hot path performs one `ArcSwap::load` and one hash lookup. Route
/// updates publish a complete replacement table; the bound socket is never
/// restarted for a membership change, so removing Service A cannot interrupt
/// Service B and adding B cannot withdraw A.
#[derive(Debug)]
pub struct NodeWaypointUdpDestinationRouter {
    listen_port: u16,
    table: arc_swap::ArcSwap<NodeWaypointUdpDestinationTable>,
    generation_counter: AtomicU64,
    refusals: AtomicU64,
}

impl NodeWaypointUdpDestinationRouter {
    /// Create a router with an empty (serve-nothing) table. An empty table is a
    /// positive fail-closed statement, not a wildcard.
    pub fn new(listen_port: u16) -> Arc<Self> {
        Arc::new(Self {
            listen_port,
            table: arc_swap::ArcSwap::from_pointee(NodeWaypointUdpDestinationTable {
                generation: 0,
                listen_port,
                routes: HashMap::new(),
            }),
            generation_counter: AtomicU64::new(0),
            refusals: AtomicU64::new(0),
        })
    }

    #[inline]
    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    /// Publish one complete accepted destination generation.
    ///
    /// `routes` must already be exact: materialization refuses duplicate
    /// `(destination, port)` claims for every ambiguous claimant, so a later
    /// duplicate here is a programming error. It is still handled fail-closed —
    /// the whole publication is refused and the previous generation retained —
    /// rather than letting insertion order pick a winner.
    pub fn publish(
        &self,
        routes: Vec<NodeWaypointUdpDestinationRoute>,
    ) -> Result<u64, NodeWaypointUdpDestinationPublishError> {
        let mut map: HashMap<IpAddr, Arc<NodeWaypointUdpDestinationRoute>> =
            HashMap::with_capacity(routes.len());
        for route in routes {
            if route.listen_port != self.listen_port {
                return Err(NodeWaypointUdpDestinationPublishError::PortMismatch);
            }
            if !destination_ip_is_admissible(route.destination) {
                return Err(NodeWaypointUdpDestinationPublishError::InadmissibleDestination);
            }
            let key = canonical_destination_ip(route.destination);
            let canonical = NodeWaypointUdpDestinationRoute {
                destination: key,
                ..route
            };
            if map.insert(key, Arc::new(canonical)).is_some() {
                return Err(NodeWaypointUdpDestinationPublishError::DuplicateDestination);
            }
        }
        let generation = self
            .generation_counter
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        self.table.store(Arc::new(NodeWaypointUdpDestinationTable {
            generation,
            listen_port: self.listen_port,
            routes: map,
        }));
        Ok(generation)
    }

    /// Retract every route without withdrawing the bound socket. Used when the
    /// owning listener leaves service so no in-flight datagram can still select
    /// a route whose serving generation is gone.
    pub fn retract(&self) -> u64 {
        self.publish(Vec::new())
            .unwrap_or_else(|_| self.table.load().generation)
    }

    /// Current accepted table snapshot.
    #[inline]
    pub fn snapshot(&self) -> Arc<NodeWaypointUdpDestinationTable> {
        self.table.load_full()
    }

    /// Total refusals observed by this router (bounded counter, no labels).
    #[inline]
    pub fn refusals(&self) -> u64 {
        self.refusals.load(Ordering::Relaxed)
    }

    /// Select the exact route for one received datagram.
    ///
    /// `local_ip` is the kernel-reported local destination ADDRESS for this
    /// datagram (`IP_PKTINFO` / `IPV6_PKTINFO`). It is the ONLY input: nothing
    /// about the client, the payload, or the numeric port alone may select a
    /// route. The port half of the exact `(destination, port)` key is the
    /// listener's own bound port, which every datagram this socket receives
    /// carries by construction.
    #[inline]
    pub fn resolve(
        &self,
        local_ip: Option<IpAddr>,
    ) -> Result<(Arc<NodeWaypointUdpDestinationRoute>, u64), (NodeWaypointUdpDestinationRefusal, u64)>
    {
        let table = self.table.load();
        let Some(local_ip) = local_ip else {
            return Err((
                NodeWaypointUdpDestinationRefusal::MissingLocalDestination,
                table.generation,
            ));
        };
        if table.routes.is_empty() {
            return Err((
                NodeWaypointUdpDestinationRefusal::NoRoutes,
                table.generation,
            ));
        }
        match table.routes.get(&canonical_destination_ip(local_ip)) {
            Some(route) => Ok((Arc::clone(route), table.generation)),
            None => Err((
                NodeWaypointUdpDestinationRefusal::UnknownDestination,
                table.generation,
            )),
        }
    }

    /// Revalidate the immutable destination + namespaced owner pinned by an
    /// established session against the current complete table.
    ///
    /// Table membership can change without rebinding the shared listener. A
    /// session therefore cannot treat its admission-time route as a lifetime
    /// capability: removal and reownership must fence both late client
    /// forwards and unsolicited backend replies. Equivalent republication of
    /// the same namespaced owner remains valid even though the route `Arc` is
    /// new.
    #[inline]
    pub fn revalidate_owner(
        &self,
        destination: IpAddr,
        owner: &NamespacedResourceId,
    ) -> Result<u64, (NodeWaypointUdpDestinationRefusal, u64)> {
        let table = self.table.load();
        if table.routes.is_empty() {
            return Err((
                NodeWaypointUdpDestinationRefusal::NoRoutes,
                table.generation,
            ));
        }
        let Some(route) = table.routes.get(&canonical_destination_ip(destination)) else {
            return Err((
                NodeWaypointUdpDestinationRefusal::UnknownDestination,
                table.generation,
            ));
        };
        if route.proxy.as_ref() != owner {
            return Err((
                NodeWaypointUdpDestinationRefusal::OwnerChanged,
                table.generation,
            ));
        }
        Ok(table.generation)
    }

    /// Rate-limited refusal warn (first, then every 100th). Carries only the
    /// listener port, the closed reason, and a counter — never a Service name,
    /// a client address, or a registry-supplied value.
    pub fn warn_refusal(&self, proxy_id: &str, refusal: NodeWaypointUdpDestinationRefusal) {
        let n = self.refusals.fetch_add(1, Ordering::Relaxed) + 1;
        if n == 1 || n.is_multiple_of(100) {
            warn!(
                proxy_id = %proxy_id,
                listen_port = self.listen_port,
                reason = refusal.as_str(),
                refusals = n,
                "Refused a NodeWaypoint UDP datagram with no exact Service destination route; \
                 nothing is forwarded and no session, backend socket or policy context is \
                 allocated for it"
            );
        }
    }

    /// Rate-limited retirement warning for an already-admitted session whose
    /// exact destination ownership is no longer current. Kept separate from
    /// [`Self::warn_refusal`] so diagnostics never claim that no session was
    /// allocated when a live session is being fenced.
    pub fn warn_session_refusal(&self, proxy_id: &str, refusal: NodeWaypointUdpDestinationRefusal) {
        let n = self.refusals.fetch_add(1, Ordering::Relaxed) + 1;
        if n == 1 || n.is_multiple_of(100) {
            warn!(
                proxy_id = %proxy_id,
                listen_port = self.listen_port,
                reason = refusal.as_str(),
                refusals = n,
                "Retired a NodeWaypoint UDP session whose exact Service destination ownership \
                 is no longer current; no further client forward or backend reply is emitted"
            );
        }
    }
}

/// Why a complete destination publication was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeWaypointUdpDestinationPublishError {
    /// A route named a port other than this listener's.
    PortMismatch,
    /// A route named an unspecified/loopback/multicast/broadcast address.
    InadmissibleDestination,
    /// Two routes claimed the same exact `(destination, port)`.
    DuplicateDestination,
}

impl std::fmt::Display for NodeWaypointUdpDestinationPublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::PortMismatch => "route listen port does not match the listener port",
            Self::InadmissibleDestination => {
                "route destination is unspecified, loopback, multicast or broadcast"
            }
            Self::DuplicateDestination => "two routes claim the same exact (destination, port)",
        };
        f.write_str(text)
    }
}

impl std::error::Error for NodeWaypointUdpDestinationPublishError {}
