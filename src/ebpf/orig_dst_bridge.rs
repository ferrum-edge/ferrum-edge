//! Original-destination → node-waypoint identity bridge (GAP-1b).
//!
//! In node-waypoint topology one mesh-proxy listener accepts traffic for many
//! pods. The eBPF `connect4`/`connect6` programs (running in each source pod's
//! cgroup) record the original destination keyed by socket cookie into the
//! `FERRUM_ORIG_DST4`/`FERRUM_ORIG_DST6` LRU maps, stamped with the source
//! pod's UID and SPIFFE hash (see `ebpf/ferrum-ebpf/src/connect{4,6}.rs` and
//! `FERRUM_WORKLOAD_IDENTITY`). The node-agent pins those maps at the
//! well-known paths.
//!
//! This bridge runs inside the **mesh-proxy** (node-waypoint topology). It
//! opens the pinned maps by path and mirrors their records into the
//! [`NodeWaypointIdentityResolver`], giving `record_orig_dst4`/
//! `record_orig_dst6` their first production caller (before this they had no
//! caller and the resolver's cookie map was always empty).
//!
//! ## Connect-side vs accept-side cookie (GAP-2M bridge)
//!
//! `connect4`/`connect6` key each record by the *source pod's
//! connecting-socket* cookie (`bpf_get_socket_cookie` on the connect socket).
//! The proxy accept path, however, resolves by the *accepted server-side
//! socket's* `SO_COOKIE` (`resolve_stream` → `socket_cookie(accepted_stream)`),
//! which is a different kernel socket with a different cookie — see the
//! invariant documented in `src/socket_opts.rs`.
//!
//! The **GAP-2M accept-side bridge is now implemented in the kernel `sock_ops`
//! program** (`ebpf/ferrum-ebpf/src/sock_ops.rs`): at active-established it
//! re-keys the connect-side record by the connection 4-tuple, and at
//! passive-established it re-stamps that record into `FERRUM_ORIG_DST4`/
//! `FERRUM_ORIG_DST6` under the *accept-side* cookie. This bridge therefore
//! mirrors accept-side-cookie records too, so the accept path's `SO_COOKIE`
//! lookup resolves the source identity without any change to this module.
//!
//! **Verification status:** CI compile-checks the kernel program
//! (`build-ebpf`) and loads + attaches it on a real ≥5.7 kernel (`ebpf-live`).
//! The full connect→capture→accept datapath (which would confirm the tuple
//! byte-order and end-to-end resolution) is not exercised by CI and remains a
//! live multi-pod-node verification step. A tuple/byte-order mismatch fails
//! closed (no accept-side record written), never misattributes identity, so
//! the unverified path is safe-by-construction. Pod-identity enrollment into
//! `identities_by_pod_uid` is wired: the resolver lazily enrolls
//! `pod_uid` → identity by hash-joining the eBPF-stamped
//! `(pod_uid, workload_spiffe_hash)` against the slice's
//! `workload_spiffe_hash` → SPIFFE index (installed at slice apply), so
//! resolution is complete end-to-end in code.
//!
//! ## Why polling
//!
//! The orig-dst maps are LRU hash maps, not ringbufs: the kernel does not
//! signal userspace on insert. The bridge therefore polls on a short interval
//! and re-syncs the resolver's cookie records from the live map. Stale cookies
//! (sockets the kernel evicted from the LRU, or closed connections) are aged
//! out of the resolver so its map cannot grow unboundedly relative to the BPF
//! map.
//!
//! **Between-tick freshness** is handled by a synchronous fallback: this bridge
//! installs a closure on the resolver (via `set_cookie_fallback`) that reads the
//! current pinned maps directly. When the accept path hits a cookie the poll
//! has not mirrored yet, `resolve_cookie` consults that fallback (one BPF
//! lookup) instead of dropping the connection until the next tick — so a
//! freshly accepted connection resolves on the first try. The maps are shared
//! via `ArcSwap` so a node-agent restart re-open transparently re-points the
//! fallback.
//!
//! One known limitation of this staged polling design remains:
//! - **Full re-sync cost.** Each tick currently re-scans both maps in full
//!   (≈2 syscalls per LRU entry) and re-inserts every record; on a busy node
//!   this should become an incremental or ringbuf-driven sync. (The poll still
//!   ages out evicted/closed cookies; the synchronous fallback only covers the
//!   freshly-accepted miss case.)
//!
//! ## Startup race and node-agent restart
//!
//! Like the SOCK_OPS consumer, the mesh-proxy may start before the node-agent
//! has pinned the maps; the bridge retries with backoff. A node-agent restart
//! re-pins fresh maps at the same path (new inode); the bridge re-stats the
//! pin and re-opens so it never reads an orphaned map.
//!
//! ## Build matrix
//!
//! The real reader is `#[cfg(all(feature = "ebpf", target_os = "linux"))]`.
//! Every other build (the shipping default, macOS dev, Windows) gets the
//! no-op stub: it logs once that no orig-dst bridge runs and returns, so the
//! resolver stays empty and the accept path fails closed — exactly the
//! documented degraded behavior.

#![allow(dead_code)]

use std::sync::Arc;

use crate::modes::mesh::node_waypoint::NodeWaypointIdentityResolver;

/// Default poll interval for the orig-dst bridge. Short enough that a cookie
/// record is mirrored into the resolver well within a TCP handshake's worth of
/// time after the source pod's `connect()`, but long enough that the map scan
/// is negligible on a busy node.
pub const ORIG_DST_BRIDGE_POLL_INTERVAL_MS: u64 = 200;

/// Run the orig-dst bridge until the shutdown signal fires.
///
/// On builds without the eBPF feature (or off Linux) this logs once and
/// returns immediately; the resolver stays empty so the node-waypoint accept
/// path fails closed on every cookie. Spawn via
/// `tokio::spawn(run_orig_dst_bridge(...))`.
pub async fn run_orig_dst_bridge(
    resolver: Arc<NodeWaypointIdentityResolver>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    {
        production::run_pinned_bridge(resolver, shutdown_rx).await
    }
    #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
    {
        let _ = resolver;
        let _ = shutdown_rx;
        tracing::warn!(
            "Node-waypoint orig-dst bridge skipped: this build has no eBPF capture \
             (built without the `ebpf` feature or non-Linux target). Source identity \
             cannot be recovered from socket cookies, so every node-waypoint accept \
             will fail closed. Run a node-agent-capable Linux image built with \
             --features ebpf to enable ambient capture."
        );
        Ok(())
    }
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod production {
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use aya::maps::{HashMap as BpfHashMap, Map, MapData};
    use ferrum_ebpf_common::{OrigDst4, OrigDst6, OrigDstKey};
    use tracing::{debug, info, warn};

    use super::ORIG_DST_BRIDGE_POLL_INTERVAL_MS;
    use crate::ebpf::{BPF_ORIG_DST4_PIN_PATH, BPF_ORIG_DST6_PIN_PATH};
    use crate::modes::mesh::node_waypoint::NodeWaypointIdentityResolver;

    type OrigDst4Map = BpfHashMap<MapData, OrigDstKey, OrigDst4>;
    type OrigDst6Map = BpfHashMap<MapData, OrigDstKey, OrigDst6>;

    const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
    const BACKOFF_MAX: Duration = Duration::from_secs(30);
    /// Re-stat the pin paths this often to catch a node-agent restart that
    /// re-pinned fresh maps at the same path (new inode).
    const INODE_CHECK_INTERVAL: Duration = Duration::from_secs(30);

    pub async fn run_pinned_bridge(
        resolver: Arc<NodeWaypointIdentityResolver>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let (initial_maps, mut inodes) = match wait_for_pinned_maps(&mut shutdown_rx).await {
            WaitOutcome::Found(pair) => pair,
            WaitOutcome::Shutdown => {
                info!("Node-waypoint orig-dst bridge shutting down before maps were pinned");
                return Ok(());
            }
        };

        info!(
            orig_dst4_pin = BPF_ORIG_DST4_PIN_PATH,
            orig_dst6_pin = BPF_ORIG_DST6_PIN_PATH,
            "Node-waypoint orig-dst bridge attached; mirroring cookie records into resolver"
        );

        // Share the open maps so the accept-path synchronous fallback can read
        // the pinned maps directly between poll ticks while this task keeps
        // polling and re-opens on node-agent restart. `ArcSwap` lets a re-open
        // publish fresh maps without the fallback having to re-install.
        let maps = Arc::new(ArcSwap::from_pointee(initial_maps));

        // GAP-2M: install the synchronous accept-path cookie fallback. On a
        // resolver miss (a cookie stamped on the accept side since the last
        // poll), the resolver reads the current pinned maps directly — one BPF
        // lookup — instead of dropping the connection until the next poll tick.
        {
            let maps = maps.clone();
            resolver
                .set_cookie_fallback(Box::new(move |cookie| lookup_cookie(&maps.load(), cookie)));
        }

        let mut poll =
            tokio::time::interval(Duration::from_millis(ORIG_DST_BRIDGE_POLL_INTERVAL_MS));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut inode_check = tokio::time::interval(INODE_CHECK_INTERVAL);
        inode_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Node-waypoint orig-dst bridge shutting down");
                        // Drop the fallback so the resolver no longer references
                        // these maps once this task (and the maps) go away.
                        resolver.clear_cookie_fallback();
                        return Ok(());
                    }
                }
                _ = poll.tick() => {
                    sync_once(&maps.load(), &resolver);
                }
                _ = inode_check.tick() => {
                    let current = MapInodes::read();
                    if current != inodes {
                        warn!(
                            "Orig-dst pin inode changed (node-agent restart); re-opening maps"
                        );
                        match open_pinned_maps() {
                            Some((reopened, reopened_inodes)) => {
                                // Publish the fresh maps; the fallback closure
                                // sees them on its next `load()`.
                                maps.store(Arc::new(reopened));
                                inodes = reopened_inodes;
                                // The resolver's cookie records reference the
                                // previous map generation; clear them so a
                                // stale cookie cannot resolve to an evicted
                                // pod. The next poll re-populates from the
                                // fresh map.
                                resolver.clear_cookie_records();
                            }
                            None => {
                                debug!(
                                    "Orig-dst maps not yet re-pinnable after inode change; \
                                     retrying on next inode check"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Synchronous single-cookie lookup backing the accept-path fallback.
    /// Returns `(pod_uid, workload_spiffe_hash, original destination)` when the
    /// cookie is present in either pinned orig-dst map. One BPF map lookup per
    /// family; invoked only on a resolver miss, so it stays off the steady-state
    /// hot path.
    fn lookup_cookie(maps: &OpenMaps, cookie: u64) -> Option<([u8; 16], u64, SocketAddr)> {
        let key = OrigDstKey { cookie };
        if let Ok(record) = maps.orig_dst4.get(&key, 0) {
            return Some((
                record.pod_uid,
                record.workload_spiffe_hash,
                orig_dst4_socket_addr(&record),
            ));
        }
        if let Ok(record) = maps.orig_dst6.get(&key, 0) {
            return Some((
                record.pod_uid,
                record.workload_spiffe_hash,
                orig_dst6_socket_addr(&record),
            ));
        }
        None
    }

    fn orig_dst4_socket_addr(record: &OrigDst4) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(record.addr.to_ne_bytes())),
            record.port as u16,
        )
    }

    fn orig_dst6_socket_addr(record: &OrigDst6) -> SocketAddr {
        let mut octets = [0u8; 16];
        for (idx, word) in record.addr.iter().enumerate() {
            octets[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_ne_bytes());
        }
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), record.port as u16)
    }

    /// One poll: re-sync the resolver's cookie records from the live BPF maps.
    /// New/updated cookies are inserted; cookies the kernel evicted from the
    /// LRU are removed from the resolver so its map tracks the BPF map.
    fn sync_once(maps: &OpenMaps, resolver: &NodeWaypointIdentityResolver) {
        let mut live_cookies: HashSet<u64> = HashSet::new();

        for result in maps.orig_dst4.iter() {
            match result {
                Ok((key, record)) => {
                    live_cookies.insert(key.cookie);
                    resolver.record_orig_dst4(key.cookie, record);
                }
                Err(e) => {
                    debug!(error = %e, "orig-dst4 map iteration error; skipping entry");
                }
            }
        }
        for result in maps.orig_dst6.iter() {
            match result {
                Ok((key, record)) => {
                    live_cookies.insert(key.cookie);
                    resolver.record_orig_dst6(key.cookie, record);
                }
                Err(e) => {
                    debug!(error = %e, "orig-dst6 map iteration error; skipping entry");
                }
            }
        }

        resolver.retain_cookie_records(&live_cookies);
    }

    struct OpenMaps {
        orig_dst4: OrigDst4Map,
        orig_dst6: OrigDst6Map,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct MapInodes {
        v4: Option<u64>,
        v6: Option<u64>,
    }

    impl MapInodes {
        fn read() -> Self {
            Self {
                v4: pin_inode(BPF_ORIG_DST4_PIN_PATH),
                v6: pin_inode(BPF_ORIG_DST6_PIN_PATH),
            }
        }
    }

    enum WaitOutcome {
        Found((OpenMaps, MapInodes)),
        Shutdown,
    }

    async fn wait_for_pinned_maps(
        shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> WaitOutcome {
        let mut backoff = BACKOFF_INITIAL;
        loop {
            if *shutdown_rx.borrow() {
                return WaitOutcome::Shutdown;
            }
            if let Some((maps, inodes)) = open_pinned_maps() {
                return WaitOutcome::Found((maps, inodes));
            }
            debug!(
                orig_dst4_pin = BPF_ORIG_DST4_PIN_PATH,
                backoff_secs = backoff.as_secs(),
                "Orig-dst maps not pinned yet (node-agent may still be starting); retrying"
            );
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        return WaitOutcome::Shutdown;
                    }
                }
            }
        }
    }

    fn open_pinned_maps() -> Option<(OpenMaps, MapInodes)> {
        let v4_data = MapData::from_pin(BPF_ORIG_DST4_PIN_PATH).ok()?;
        let orig_dst4 = OrigDst4Map::try_from(Map::LruHashMap(v4_data))
            .map_err(|e| warn!(error = %e, "FERRUM_ORIG_DST4 pin type mismatch"))
            .ok()?;
        let v6_data = MapData::from_pin(BPF_ORIG_DST6_PIN_PATH).ok()?;
        let orig_dst6 = OrigDst6Map::try_from(Map::LruHashMap(v6_data))
            .map_err(|e| warn!(error = %e, "FERRUM_ORIG_DST6 pin type mismatch"))
            .ok()?;
        let inodes = MapInodes::read();
        Some((
            OpenMaps {
                orig_dst4,
                orig_dst6,
            },
            inodes,
        ))
    }

    fn pin_inode(path: &str) -> Option<u64> {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|meta| meta.ino())
    }
}
