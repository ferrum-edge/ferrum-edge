//! Batched UDP receive using `recvmmsg(2)` on Linux.
//!
//! Receives multiple datagrams in a single kernel crossing, reducing syscall
//! overhead for high-throughput UDP proxy workloads. On non-Linux platforms,
//! this module provides a no-op stub (the UDP proxy falls back to individual
//! `try_recv_from` calls via the `#[cfg]` gate at the call site).
//!
//! **Performance impact**: Each `recvfrom` call (what `try_recv_from` does
//! internally) is a separate syscall. At 100K+ datagrams/sec, syscall overhead
//! dominates. `recvmmsg` amortizes a single kernel crossing across up to N
//! datagrams, matching the approach Envoy uses via kernel-level GRO.
//!
//! **Default batch size**: 64 datagrams per `recvmmsg` call. Configurable via
//! `FERRUM_UDP_RECVMMSG_BATCH_SIZE`. The drain loop calls `recvmmsg` repeatedly
//! up to the adaptive `batch_limit`, so total datagrams drained per cycle can
//! exceed the batch size.

#[cfg(all(target_os = "linux", feature = "bench-udp-profile"))]
use crate::udp_profile::BatchField;

#[cfg(target_os = "linux")]
use std::net::SocketAddr;

/// Pre-allocated buffers for batched UDP receive via `recvmmsg(2)`.
///
/// Allocates `batch_size` datagram buffers (each `MAX_DGRAM_SIZE` bytes),
/// plus the corresponding `iovec`, `mmsghdr`, and `sockaddr_storage` arrays.
/// All memory is allocated once at listener startup and reused across calls.
///
/// Only available on Linux. On other platforms, the UDP proxy uses the
/// existing `try_recv_from` drain loop with no change in behavior.
#[cfg(target_os = "linux")]
pub struct RecvMmsgBatch {
    #[cfg(feature = "bench-udp-profile")]
    pub profile_direction: crate::udp_profile::Direction,
    /// Per-slot uninitialized datagram buffers. Slot `i` starts at L1D-staggered
    /// offset `(i & 7) * 512` bytes to avoid 64 KiB cache-set aliasing across
    /// burst receives while keeping untouched tail pages unfaulted.
    bufs: Vec<Vec<std::mem::MaybeUninit<u8>>>,
    /// Per-slot source addresses (converted from sockaddr_storage after recv).
    result_addrs: Vec<SocketAddr>,
    /// Per-slot received datagram lengths (from mmsghdr.msg_len).
    result_lens: Vec<u32>,
    /// Pre-allocated sockaddr_storage for recvmmsg (kernel writes source addrs here).
    raw_addrs: Vec<libc::sockaddr_storage>,
    /// Pre-allocated iovec array (one per slot, pointing into bufs).
    iovecs: Vec<libc::iovec>,
    /// Pre-allocated mmsghdr array (one per slot).
    msgs: Vec<libc::mmsghdr>,
    /// Contiguous flat cmsg buffer (`capacity * cmsg_hdrs_per_slot` headers)
    /// sized for UDP_GRO + IP_PKTINFO / IPV6_PKTINFO (+ optional
    /// RECVORIGDSTADDR). Backed by `Vec<libc::cmsghdr>` so every slot base is
    /// strictly `cmsghdr`-aligned by the type system.
    cmsg_buf: Vec<libc::cmsghdr>,
    /// Number of `libc::cmsghdr` elements reserved per slot.
    cmsg_hdrs_per_slot: usize,
    /// Byte length per slot in `cmsg_buf`.
    cmsg_stride: usize,
    /// Per-slot GRO segment size parsed from cmsg after recvmmsg.
    /// `None` = single datagram (no GRO coalescing), `Some(n)` = coalesced with segment size n.
    gro_segments: Vec<Option<u16>>,
    /// Per-slot captured local (reply-source) address from IP(v6)_PKTINFO
    /// cmsg. The interface index is preserved alongside the address so scoped
    /// IPv6 replies (notably link-local `fe80::/10`) egress the correct
    /// interface zone on send; for IPv4 it's informational.
    local_addrs: Vec<Option<crate::socket_opts::PktinfoLocal>>,
    /// Per-slot original (pre-`TPROXY`) destination address parsed from the
    /// IP(v6)_RECVORIGDSTADDR cmsg. `None` unless the socket has
    /// `IP_RECVORIGDSTADDR` / `IPV6_RECVORIGDSTADDR` enabled (the mesh UDP
    /// capture listener does; plain UDP proxy listeners do not). This is how a
    /// TPROXY-captured datagram recovers the `service:port` the pod dialed,
    /// since TPROXY delivers without rewriting the destination.
    orig_dsts: Vec<Option<SocketAddr>>,
    /// Whether to parse the IP(v6)_RECVORIGDSTADDR cmsg per datagram. Enabled
    /// ONLY for the mesh UDP capture listener (which sets `IP_RECVORIGDSTADDR`);
    /// plain UDP proxy listeners leave it `false` so they do not pay an
    /// ancillary-data scan on every datagram for a value that is always `None`
    /// there (codex r2 P2).
    parse_orig_dst: bool,
    /// Maximum datagrams per recvmmsg call.
    capacity: usize,
    /// Number of datagrams received in the last `recv()` call.
    count: usize,
}

#[cfg(target_os = "linux")]
const MAX_DGRAM_SIZE: usize = 65535;

/// Preferred per-slot datagram buffer size for `SendMmsgBatch`.
///
/// Sized near a typical path-MTU payload (Ethernet ~1500) with headroom so
/// ordinary DNS/QUIC/game-server replies fit without growing. Slots are
/// allocated lazily on first use; datagrams larger than this cap are refused
/// by `push_with_local` so the UDP reply path can use the existing
/// `direct_send_to_client` escape hatch (full UDP datagrams up to
/// [`MAX_DGRAM_SIZE`] remain supported).
#[cfg(target_os = "linux")]
pub const SEND_MMSG_SLOT_SIZE: usize = 2048;

/// Result of attempting to queue a datagram into a [`SendMmsgBatch`].
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendMmsgPushResult {
    /// Datagram was copied into a free slot.
    Queued,
    /// No free slots; caller should flush and retry.
    Full,
    /// Datagram exceeds the batch slot size (but is within the UDP maximum).
    /// The batch is unchanged; caller should send via the direct-send path.
    Oversized,
}

// SAFETY: The raw pointers in `iovecs` (`*mut c_void`) and `msgs` (`*mut iovec`)
// point into fixed-size heap `Vec` buffers (`bufs`, `raw_addrs`, `iovecs`,
// `cmsg_buf`) owned by this struct that never resize or reallocate after
// `new()`. They are only dereferenced inside `recv()`. The struct is
// exclusively owned by a single tokio task (the UDP listener loop).
#[cfg(target_os = "linux")]
unsafe impl Send for RecvMmsgBatch {}

#[cfg(target_os = "linux")]
impl RecvMmsgBatch {
    /// Create a new batch with pre-allocated buffers for `capacity` datagrams.
    ///
    /// Allocates `capacity * 65535` bytes for datagram buffers plus bookkeeping
    /// arrays. This is a one-time allocation at listener startup.
    ///
    /// `parse_orig_dst` opts this batch into per-datagram
    /// `IP_RECVORIGDSTADDR` cmsg parsing; pass `true` only for the mesh UDP
    /// capture listener and `false` for plain UDP proxy listeners (which never
    /// enable the socket option and so would scan ancillary data for nothing).
    pub fn new(capacity: usize, parse_orig_dst: bool) -> Self {
        let capacity = capacity.max(1);
        // cmsg buffer must hold UDP_GRO (u16) + IP_PKTINFO / IPV6_PKTINFO in the
        // same allocation; sized for the v6 worst case so both families fit.
        // Backed by `Vec<libc::cmsghdr>` so every slot is guaranteed aligned
        // for `CMSG_FIRSTHDR`/`CMSG_NXTHDR`.
        let hdr_size = std::mem::size_of::<libc::cmsghdr>();
        let cmsg_raw = crate::socket_opts::recv_cmsg_space();
        let cmsg_hdrs_per_slot = cmsg_raw.div_ceil(hdr_size).max(1);
        let cmsg_stride = cmsg_hdrs_per_slot * hdr_size;
        Self {
            #[cfg(feature = "bench-udp-profile")]
            profile_direction: crate::udp_profile::Direction::Other,
            bufs: (0..capacity)
                .map(|i| {
                    let cap = MAX_DGRAM_SIZE + (i & 7) * 512;
                    let mut v = Vec::<std::mem::MaybeUninit<u8>>::with_capacity(cap);
                    // SAFETY: `MaybeUninit<u8>` requires no initialization; the
                    // kernel writes `msg_len` bytes starting at `(i & 7) * 512`
                    // before `datagram(i)` reads them.
                    unsafe { v.set_len(cap) };
                    v
                })
                .collect(),
            result_addrs: vec![SocketAddr::from(([0, 0, 0, 0], 0)); capacity],
            result_lens: vec![0u32; capacity],
            raw_addrs: vec![unsafe { std::mem::zeroed() }; capacity],
            iovecs: vec![
                libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                };
                capacity
            ],
            msgs: vec![unsafe { std::mem::zeroed() }; capacity],
            cmsg_buf: vec![unsafe { std::mem::zeroed() }; capacity * cmsg_hdrs_per_slot],
            cmsg_hdrs_per_slot,
            cmsg_stride,
            gro_segments: vec![None; capacity],
            local_addrs: vec![None; capacity],
            orig_dsts: vec![None; capacity],
            parse_orig_dst,
            capacity,
            count: 0,
        }
    }

    /// Maximum datagrams this batch can receive in a single call.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the datagram data and source address for slot `i`.
    ///
    /// # Panics
    /// Panics (debug) if `i` is out of bounds.
    pub fn datagram(&self, i: usize) -> (&[u8], SocketAddr) {
        debug_assert!(i < self.count);
        let offset = (i & 7) * 512;
        let len = (self.result_lens[i] as usize).min(MAX_DGRAM_SIZE);
        // SAFETY: `recvmmsg` wrote `len` initialized bytes at `bufs[i][offset..]`.
        let slice = unsafe {
            std::slice::from_raw_parts(self.bufs[i].as_ptr().add(offset).cast::<u8>(), len)
        };
        (slice, self.result_addrs[i])
    }

    /// Returns the GRO segment size for slot `i`, if the kernel coalesced
    /// multiple datagrams into one buffer via UDP_GRO.
    ///
    /// Returns `None` for single (non-coalesced) datagrams.
    /// When `Some(seg_size)`, the datagram data should be split into
    /// `seg_size`-byte chunks (the last chunk may be shorter).
    pub fn gro_segment_size(&self, i: usize) -> Option<u16> {
        debug_assert!(i < self.count);
        self.gro_segments[i]
    }

    /// Returns the captured local (reply-source) address + interface index for
    /// slot `i`, parsed from the IP(v6)_PKTINFO cmsg. `None` when pktinfo is
    /// disabled or the socket is not wildcard-bound. The ifindex is required
    /// for scoped IPv6 (link-local) reply correctness.
    pub fn local_addr(&self, i: usize) -> Option<crate::socket_opts::PktinfoLocal> {
        debug_assert!(i < self.count);
        self.local_addrs[i]
    }

    /// Returns the original (pre-`TPROXY`) destination address for slot `i`,
    /// parsed from the IP(v6)_RECVORIGDSTADDR cmsg. `None` when the socket does
    /// not have `IP_RECVORIGDSTADDR` / `IPV6_RECVORIGDSTADDR` enabled or the
    /// datagram carried no such cmsg. The mesh UDP capture listener keys each
    /// session by `(client, orig-dst)` from this value.
    pub fn orig_dst(&self, i: usize) -> Option<SocketAddr> {
        debug_assert!(i < self.count);
        self.orig_dsts[i]
    }

    /// Receive up to `max_count` datagrams in a single `recvmmsg` syscall.
    ///
    /// Uses `MSG_DONTWAIT` for non-blocking operation. Returns `Ok(n)` where
    /// `n > 0` on success, or `Err` with `ErrorKind::WouldBlock` when no data
    /// is available (socket drained).
    ///
    /// After a successful call, use `count()` and `datagram(i)` to iterate
    /// the received datagrams.
    ///
    /// # Safety
    /// Calls `libc::recvmmsg` which writes into pre-allocated buffers via raw
    /// pointers. Safe because:
    /// - Buffers (`bufs`) are heap-allocated Vecs that don't move or resize
    /// - Pointer arrays (`iovecs`, `msgs`, `raw_addrs`) are rebuilt before each call
    /// - The batch outlives the syscall (no dangling pointers)
    pub fn recv(&mut self, fd: std::os::fd::RawFd, max_count: usize) -> std::io::Result<usize> {
        let n = max_count.min(self.capacity);
        if n == 0 {
            self.count = 0;
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }

        // Derive all slot pointers fresh from a single `as_mut_ptr()` base per
        // `Vec` immediately before `recvmmsg` so every raw pointer carries valid
        // mutable provenance under Stacked/Tree Borrows (never indexing `&mut`
        // slices across slots). `raw_addrs`, `cmsg_buf`, and `bufs` are not
        // pre-zeroed because the kernel writes `msg_namelen` / `msg_controllen`
        // / `msg_len` bytes and reports each length back.
        let addr_cap = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let cmsg_stride = self.cmsg_stride;
        let cmsg_hdrs_per_slot = self.cmsg_hdrs_per_slot;
        let raw_addrs_base = self.raw_addrs.as_mut_ptr();
        let iovecs_base = self.iovecs.as_mut_ptr();
        let cmsg_base = self.cmsg_buf.as_mut_ptr();
        let msgs_base = self.msgs.as_mut_ptr();
        let bufs_base = self.bufs.as_mut_ptr();
        unsafe {
            for i in 0..n {
                let offset = (i & 7) * 512;
                let iov_ptr = iovecs_base.add(i);
                *iov_ptr = libc::iovec {
                    iov_base: (*bufs_base.add(i)).as_mut_ptr().add(offset) as *mut libc::c_void,
                    iov_len: MAX_DGRAM_SIZE,
                };
                let msg_ptr = msgs_base.add(i);
                let hdr = &mut (*msg_ptr).msg_hdr;
                hdr.msg_name = raw_addrs_base.add(i) as *mut libc::c_void;
                hdr.msg_namelen = addr_cap;
                hdr.msg_iov = iov_ptr;
                hdr.msg_iovlen = 1;
                hdr.msg_control = cmsg_base.add(i * cmsg_hdrs_per_slot) as *mut libc::c_void;
                hdr.msg_controllen = cmsg_stride;
                hdr.msg_flags = 0;
                (*msg_ptr).msg_len = 0;
            }
        }

        // Single syscall to receive up to n datagrams.
        let ret = unsafe {
            libc::recvmmsg(
                fd,
                msgs_base,
                n as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(), // no timeout
            )
        };

        if ret < 0 {
            let error = std::io::Error::last_os_error();
            #[cfg(feature = "bench-udp-profile")]
            crate::udp_profile::recvmmsg(self.profile_direction, n, &Err(error.kind().into()));
            self.count = 0;
            return Err(error);
        }

        let received = ret as usize;
        #[cfg(feature = "bench-udp-profile")]
        {
            crate::udp_profile::recvmmsg(self.profile_direction, n, &Ok(received));
            let bytes: usize = self
                .msgs
                .iter()
                .take(received)
                .map(|m| m.msg_len as usize)
                .sum();
            crate::udp_profile::batch_count(self.profile_direction, BatchField::RxBytes, bytes);
        }
        // Hoisted (Copy bool) so the per-datagram loop never re-reads the field
        // and so plain UDP proxy listeners skip the orig-dst cmsg scan entirely.
        let parse_orig_dst = self.parse_orig_dst;
        for i in 0..received {
            self.result_lens[i] = self.msgs[i].msg_len;
            #[cfg(feature = "bench-udp-profile")]
            let address =
                sockaddr_storage_to_std(&self.raw_addrs[i], self.msgs[i].msg_hdr.msg_namelen)
                    .inspect_err(|_| {
                        crate::udp_profile::batch_count(
                            self.profile_direction,
                            BatchField::RxParseErrors,
                            1,
                        );
                    });
            #[cfg(not(feature = "bench-udp-profile"))]
            let address =
                sockaddr_storage_to_std(&self.raw_addrs[i], self.msgs[i].msg_hdr.msg_namelen);
            self.result_addrs[i] = address?;
            // Single-pass parse of GRO, IP(v6)_PKTINFO, and optional orig-dst
            // ancillary messages. Exits immediately when `msg_controllen == 0`.
            // SAFETY: `self.msgs[i].msg_hdr` was just populated by `recvmmsg`
            // with `msg_control` pointing into our `cmsghdr`-aligned `cmsg_buf`.
            let cmsgs = unsafe {
                crate::socket_opts::extract_recv_cmsgs(&self.msgs[i].msg_hdr, parse_orig_dst)
            };
            self.gro_segments[i] = cmsgs.gro_segment;
            #[cfg(feature = "bench-udp-profile")]
            {
                if self.msgs[i].msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                    udp_count!(RecvTruncatedSlots, 1);
                }
                if self.msgs[i].msg_hdr.msg_flags & libc::MSG_CTRUNC != 0 {
                    udp_count!(RecvControlTruncatedSlots, 1);
                }
                if self.gro_segments[i] == Some(0) {
                    udp_count!(RecvInvalidGroSegment, 1);
                }
                let bytes = self.result_lens[i] as usize;
                let packets = match self.gro_segments[i].filter(|size| *size > 0) {
                    Some(size) => bytes.div_ceil(usize::from(size)),
                    None => 1,
                };
                crate::udp_profile::batch_count(
                    self.profile_direction,
                    BatchField::RxLogicalPackets,
                    packets,
                );
                if self.gro_segments[i].is_some() {
                    crate::udp_profile::batch_count(
                        self.profile_direction,
                        BatchField::RxGroSlots,
                        1,
                    );
                    crate::udp_profile::batch_count(
                        self.profile_direction,
                        BatchField::RxGroPackets,
                        packets,
                    );
                    crate::udp_profile::batch_count(
                        self.profile_direction,
                        BatchField::RxGroBytes,
                        bytes,
                    );
                }
            }
            self.local_addrs[i] = cmsgs.pktinfo;
            self.orig_dsts[i] = cmsgs.orig_dst;
        }
        self.count = received;
        Ok(received)
    }
}

/// Convert a `libc::sockaddr_storage` to `std::net::SocketAddr`, verifying
/// that `addr_len` covers the address family's sockaddr struct.
#[cfg(target_os = "linux")]
#[inline]
fn sockaddr_storage_to_std(
    addr: &libc::sockaddr_storage,
    addr_len: libc::socklen_t,
) -> std::io::Result<SocketAddr> {
    if (addr_len as usize) < std::mem::size_of::<libc::sa_family_t>() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "truncated sockaddr from recvmmsg",
        ));
    }
    match addr.ss_family as libc::c_int {
        libc::AF_INET => {
            if (addr_len as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "truncated IPv4 sockaddr from recvmmsg",
                ));
            }
            let a = unsafe { &*(addr as *const _ as *const libc::sockaddr_in) };
            Ok(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))),
                u16::from_be(a.sin_port),
            ))
        }
        libc::AF_INET6 => {
            if (addr_len as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "truncated IPv6 sockaddr from recvmmsg",
                ));
            }
            let a = unsafe { &*(addr as *const _ as *const libc::sockaddr_in6) };
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            )))
        }
        family => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported address family: {}", family),
        )),
    }
}

/// Lightweight batched receive for a connected plain-UDP backend socket.
///
/// Connected backend sockets need neither source addresses (`msg_name = NULL`)
/// nor ancillary control messages (`msg_control = NULL`). Slot payload buffers
/// are allocated uninitialized (`MaybeUninit<u8>`) so spare slots beyond the
/// first datagram never fault pages or pollute L1/L2 cache during single-packet
/// request/response exchanges, while bursts still drain up to `capacity`
/// datagrams in a single `recvmmsg(2)` crossing.
///
/// When `recvmmsg(fd, msgs, n, MSG_DONTWAIT, NULL)` returns `0 < k < n`, the
/// kernel already drained the socket queue to `EAGAIN` inside that single
/// syscall, allowing the caller to clear Tokio's edge-triggered readiness
/// without issuing a trailing `try_recv()` syscall.
#[cfg(target_os = "linux")]
pub struct BackendRecvBatch {
    #[cfg(feature = "bench-udp-profile")]
    pub profile_direction: crate::udp_profile::Direction,
    bufs: Vec<Vec<std::mem::MaybeUninit<u8>>>,
    iovecs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
    capacity: usize,
    count: usize,
}

// SAFETY: `iovecs` and `msgs` pointers are derived fresh from `as_mut_ptr()`
// inside `recv()` right before each `recvmmsg` syscall and never outlive it.
// Owned exclusively by one per-session reply task.
#[cfg(target_os = "linux")]
unsafe impl Send for BackendRecvBatch {}

#[cfg(target_os = "linux")]
impl BackendRecvBatch {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let bufs = (0..capacity)
            .map(|_| {
                let mut buf = Vec::<std::mem::MaybeUninit<u8>>::with_capacity(MAX_DGRAM_SIZE);
                // SAFETY: `MaybeUninit<u8>` requires no initialization; the
                // kernel writes `msg_len` bytes before `datagram()` reads them.
                unsafe { buf.set_len(MAX_DGRAM_SIZE) };
                buf
            })
            .collect();
        Self {
            #[cfg(feature = "bench-udp-profile")]
            profile_direction: crate::udp_profile::Direction::Reply,
            bufs,
            iovecs: vec![
                libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                };
                capacity
            ],
            msgs: vec![unsafe { std::mem::zeroed() }; capacity],
            capacity,
            count: 0,
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Lazily grow slot capacity (e.g. from 2 to 4 on the first observed reply
    /// burst) while keeping steady-state 1-for-1 sessions at minimal memory.
    pub fn grow_to(&mut self, new_capacity: usize) {
        if new_capacity <= self.capacity {
            return;
        }
        let extra = new_capacity - self.capacity;
        self.bufs.reserve(extra);
        for _ in 0..extra {
            let mut buf = Vec::<std::mem::MaybeUninit<u8>>::with_capacity(MAX_DGRAM_SIZE);
            unsafe { buf.set_len(MAX_DGRAM_SIZE) };
            self.bufs.push(buf);
        }
        self.iovecs.resize(
            new_capacity,
            libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            },
        );
        self.msgs
            .resize(new_capacity, unsafe { std::mem::zeroed() });
        self.capacity = new_capacity;
    }

    /// Receive up to `max_count` datagrams from a connected UDP socket.
    pub fn recv(&mut self, fd: std::os::fd::RawFd, max_count: usize) -> std::io::Result<usize> {
        let n = max_count.min(self.capacity);
        if n == 0 {
            self.count = 0;
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }

        // Derive all slot pointers fresh from a single `as_mut_ptr()` base per
        // `Vec` immediately before `recvmmsg` so every pointer carries valid
        // mutable provenance under Stacked/Tree Borrows.
        let iovecs_base = self.iovecs.as_mut_ptr();
        let msgs_base = self.msgs.as_mut_ptr();
        let bufs_base = self.bufs.as_mut_ptr();
        unsafe {
            for i in 0..n {
                let iov_ptr = iovecs_base.add(i);
                *iov_ptr = libc::iovec {
                    iov_base: (*bufs_base.add(i)).as_mut_ptr() as *mut libc::c_void,
                    iov_len: MAX_DGRAM_SIZE,
                };
                let msg_ptr = msgs_base.add(i);
                let hdr = &mut (*msg_ptr).msg_hdr;
                hdr.msg_name = std::ptr::null_mut();
                hdr.msg_namelen = 0;
                hdr.msg_iov = iov_ptr;
                hdr.msg_iovlen = 1;
                hdr.msg_control = std::ptr::null_mut();
                hdr.msg_controllen = 0;
                hdr.msg_flags = 0;
                (*msg_ptr).msg_len = 0;
            }
        }

        let ret = unsafe {
            libc::recvmmsg(
                fd,
                msgs_base,
                n as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if ret < 0 {
            let error = std::io::Error::last_os_error();
            #[cfg(feature = "bench-udp-profile")]
            crate::udp_profile::recvmmsg(self.profile_direction, n, &Err(error.kind().into()));
            self.count = 0;
            return Err(error);
        }
        let received = ret as usize;
        #[cfg(feature = "bench-udp-profile")]
        {
            crate::udp_profile::recvmmsg(self.profile_direction, n, &Ok(received));
            let bytes: usize = self
                .msgs
                .iter()
                .take(received)
                .map(|m| m.msg_len as usize)
                .sum();
            crate::udp_profile::batch_count(self.profile_direction, BatchField::RxBytes, bytes);
        }
        self.count = received;
        Ok(received)
    }

    /// Payload slice for slot `i` (`i < received`).
    #[inline]
    pub fn datagram(&self, i: usize) -> &[u8] {
        debug_assert!(i < self.count);
        let len = (self.msgs[i].msg_len as usize).min(MAX_DGRAM_SIZE);
        // SAFETY: `recvmmsg` initialized the first `len` bytes of `bufs[i]`.
        unsafe { std::slice::from_raw_parts(self.bufs[i].as_ptr().cast::<u8>(), len) }
    }
}

/// Lazily-allocated buffers for batched UDP send via `sendmmsg(2)`.
///
/// Collects datagrams and their destination addresses, then flushes them all
/// in a single `sendmmsg` syscall. This reduces syscall overhead on the
/// backend→client reply path, mirroring the `recvmmsg` optimization on recv.
///
/// Per-slot datagram buffers start empty and are allocated on first use at
/// [`SEND_MMSG_SLOT_SIZE`] (2 KiB). That avoids the historical eager
/// `capacity × 65535` (~4.2 MiB) footprint per plain-UDP session. Datagrams
/// larger than the slot size are refused (`SendMmsgPushResult::Oversized`) so
/// the reply path can `sendmsg` them directly while still supporting the full
/// valid UDP datagram size.
///
/// Only available on Linux. On other platforms, the UDP proxy falls back to
/// individual `send_to` calls.
#[cfg(target_os = "linux")]
pub struct SendMmsgBatch {
    #[cfg(feature = "bench-udp-profile")]
    pub profile_direction: crate::udp_profile::Direction,
    /// Per-slot datagram buffers (data copied in on push). Empty until the
    /// slot is first used; then sized to [`SEND_MMSG_SLOT_SIZE`].
    bufs: Vec<Vec<u8>>,
    /// Per-slot actual datagram length.
    lens: Vec<usize>,
    /// Per-slot destination addresses.
    dest_addrs: Vec<libc::sockaddr_storage>,
    /// Per-slot destination address lengths.
    dest_addr_lens: Vec<libc::socklen_t>,
    /// Pre-allocated iovec array (one per slot).
    iovecs: Vec<libc::iovec>,
    /// Pre-allocated mmsghdr array (one per slot).
    msgs: Vec<libc::mmsghdr>,
    /// Per-slot optional reply source address + interface index (from pktinfo
    /// capture on recv). When `Some`, an IP(v6)_PKTINFO cmsg is attached to
    /// this slot's msghdr so the kernel uses the captured address (and, for
    /// IPv6 link-local, the captured interface zone) as the reply source
    /// without a routing-table lookup. When `None`, the kernel picks a source
    /// via routing.
    local_ips: Vec<Option<crate::socket_opts::PktinfoLocal>>,
    /// Per-slot cmsg buffers for the optional IP(v6)_PKTINFO ancillary data.
    /// Sized for the worst case (v6 in6_pktinfo) so a single allocation handles
    /// both families. Empty when no pktinfo is attached.
    cmsg_bufs: Vec<Vec<u8>>,
    /// Maximum datagrams per sendmmsg call.
    capacity: usize,
    /// Maximum bytes stored per slot. Datagrams larger than this are refused.
    slot_size: usize,
    /// Number of datagrams queued for the next flush.
    count: usize,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct SendMmsgFlush {
    pub datagrams: usize,
    pub bytes: usize,
}

// SAFETY: Same reasoning as RecvMmsgBatch — raw pointers in iovecs/msgs point
// into Vec buffers owned by the same struct, only dereferenced inside flush()
// which rebuilds them first. Exclusively owned by a single tokio task.
#[cfg(target_os = "linux")]
unsafe impl Send for SendMmsgBatch {}

#[cfg(target_os = "linux")]
impl SendMmsgBatch {
    /// Create a send batch for `capacity` datagrams with lazy slot buffers.
    ///
    /// Bookkeeping arrays are sized up front; per-slot datagram buffers remain
    /// empty until first use (then allocated at [`SEND_MMSG_SLOT_SIZE`]).
    pub fn new(capacity: usize) -> Self {
        Self::with_slot_size(capacity, SEND_MMSG_SLOT_SIZE)
    }

    /// Create a send batch with an explicit per-slot size (clamped to
    /// `1..=MAX_DGRAM_SIZE`). Intended for tests and callers that need a
    /// non-default bound; production uses [`Self::new`].
    pub fn with_slot_size(capacity: usize, slot_size: usize) -> Self {
        let capacity = capacity.max(1);
        let slot_size = slot_size.clamp(1, MAX_DGRAM_SIZE);
        let cmsg_space =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize };
        Self {
            #[cfg(feature = "bench-udp-profile")]
            profile_direction: crate::udp_profile::Direction::Other,
            // Lazy: no eager capacity × 65535 (or even capacity × slot_size).
            bufs: (0..capacity).map(|_| Vec::new()).collect(),
            lens: vec![0usize; capacity],
            dest_addrs: vec![unsafe { std::mem::zeroed() }; capacity],
            dest_addr_lens: vec![0; capacity],
            iovecs: vec![
                libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                };
                capacity
            ],
            msgs: vec![unsafe { std::mem::zeroed() }; capacity],
            local_ips: vec![None; capacity],
            cmsg_bufs: (0..capacity).map(|_| vec![0u8; cmsg_space]).collect(),
            capacity,
            slot_size,
            count: 0,
        }
    }

    /// Maximum bytes accepted per slot by [`Self::push_with_local`].
    ///
    /// The public library's external regression tests use this accessor.
    pub fn slot_size(&self) -> usize {
        self.slot_size
    }

    /// Total capacity currently reserved across per-slot datagram buffers.
    ///
    /// Used by memory-footprint contract tests. Fresh batches report `0`
    /// because slot buffers are allocated lazily.
    pub fn datagram_buffer_capacity_bytes(&self) -> usize {
        self.bufs.iter().map(Vec::capacity).sum()
    }

    /// Ensure slot `i` has a buffer of at least `self.slot_size` bytes.
    ///
    /// Allocates on first use only — subsequent pushes into the same slot
    /// reuse the buffer (no per-datagram hot-path allocation).
    fn ensure_slot_buf(&mut self, i: usize) {
        let slot_size = self.slot_size;
        let buf = &mut self.bufs[i];
        if buf.len() < slot_size {
            buf.resize(slot_size, 0);
        }
    }

    /// Queue a datagram for batched sending, optionally attaching an
    /// IP(v6)_PKTINFO cmsg with `local` as the reply source address and
    /// interface index.
    ///
    /// Returns [`SendMmsgPushResult::Full`] if the batch has no free slots,
    /// or [`SendMmsgPushResult::Oversized`] if `data` exceeds [`Self::slot_size`]
    /// (caller should use the direct-send escape hatch). When `local` is
    /// `Some`, its address family must match `dest` — v4 pktinfo cannot be
    /// combined with a v6 destination and vice versa. Mismatches are skipped
    /// silently; the slot is queued without pktinfo so the kernel picks a
    /// source itself.
    pub fn push_with_local(
        &mut self,
        data: &[u8],
        dest: SocketAddr,
        local: Option<crate::socket_opts::PktinfoLocal>,
    ) -> SendMmsgPushResult {
        let len = data.len().min(MAX_DGRAM_SIZE);
        if len > self.slot_size {
            #[cfg(feature = "bench-udp-profile")]
            crate::udp_profile::batch_count(self.profile_direction, BatchField::TxOversized, 1);
            return SendMmsgPushResult::Oversized;
        }
        if self.count >= self.capacity {
            return SendMmsgPushResult::Full;
        }
        let i = self.count;
        self.ensure_slot_buf(i);
        self.bufs[i][..len].copy_from_slice(&data[..len]);
        self.lens[i] = len;
        let (addr, addr_len) = std_to_sockaddr_storage(dest);
        self.dest_addrs[i] = addr;
        self.dest_addr_lens[i] = addr_len;
        // Only honor local when address family matches the destination.
        self.local_ips[i] = match (local.map(|l| l.ip), dest) {
            (Some(std::net::IpAddr::V4(_)), SocketAddr::V4(_))
            | (Some(std::net::IpAddr::V6(_)), SocketAddr::V6(_)) => local,
            _ => None,
        };
        self.count += 1;
        SendMmsgPushResult::Queued
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Drop every queued datagram without sending.
    ///
    /// Allocation-free: lazily allocated slot buffers keep their capacity for
    /// reuse. After discard, [`Self::pending_stats`] is zero and a subsequent
    /// [`Self::flush`] is a no-op — discarded payloads must not be counted as
    /// sent.
    pub fn discard(&mut self) {
        #[cfg(feature = "bench-udp-profile")]
        {
            crate::udp_profile::batch_count(
                self.profile_direction,
                BatchField::TxDiscardedSlots,
                self.count,
            );
            let bytes = self.lens.iter().take(self.count).sum();
            crate::udp_profile::batch_count(
                self.profile_direction,
                BatchField::TxDiscardedBytes,
                bytes,
            );
        }
        self.count = 0;
    }

    /// Return the queued datagram and byte counts that would be lost if a
    /// final best-effort flush fails and the caller drops the remainder.
    pub fn pending_stats(&self) -> SendMmsgFlush {
        SendMmsgFlush {
            datagrams: self.count,
            bytes: self.lens.iter().take(self.count).sum(),
        }
    }

    /// Send all queued datagrams in a single `sendmmsg` syscall.
    ///
    /// Returns the datagrams/bytes successfully sent. On partial send,
    /// the caller should handle the unsent remainder (or accept the loss for
    /// UDP best-effort semantics).
    ///
    /// Successful partial sends keep the unsent remainder queued at the front
    /// for a retry. Errors clear the queue because UDP is best-effort and
    /// preserving stale datagrams would reorder/requeue across iterations.
    pub fn flush(&mut self, fd: std::os::fd::RawFd) -> std::io::Result<SendMmsgFlush> {
        if self.count == 0 {
            return Ok(SendMmsgFlush::default());
        }

        // Rebuild pointer arrays fresh from a single `as_mut_ptr()` base per
        // `Vec` before the syscall so every raw pointer has valid provenance.
        let dest_addrs_base = self.dest_addrs.as_mut_ptr();
        let iovecs_base = self.iovecs.as_mut_ptr();
        let msgs_base = self.msgs.as_mut_ptr();
        let bufs_base = self.bufs.as_mut_ptr();
        let cmsg_bufs_base = self.cmsg_bufs.as_mut_ptr();
        for i in 0..self.count {
            unsafe {
                let iov_ptr = iovecs_base.add(i);
                *iov_ptr = libc::iovec {
                    iov_base: (*bufs_base.add(i)).as_mut_ptr() as *mut libc::c_void,
                    iov_len: self.lens[i],
                };

                let msg_ptr = msgs_base.add(i);
                *msg_ptr = std::mem::zeroed();
                let hdr = &mut (*msg_ptr).msg_hdr;
                hdr.msg_name = dest_addrs_base.add(i) as *mut libc::c_void;
                hdr.msg_namelen = self.dest_addr_lens[i];
                hdr.msg_iov = iov_ptr;
                hdr.msg_iovlen = 1;

                // Attach IP(v6)_PKTINFO cmsg when a local source address is set.
                // The cmsg_buf is pre-allocated for the v6 worst case and reused.
                if let Some(local) = self.local_ips[i] {
                    let local_ip = local.ip;
                    // Send-side interface selection is derived, never the captured
                    // ingress interface: see `PktinfoLocal::send_ifindex`.
                    let send_ifindex = local.send_ifindex();
                    let cmsg_buf = &mut *cmsg_bufs_base.add(i);
                    cmsg_buf.fill(0);
                    let (pktinfo_len, pktinfo_space) = match local_ip {
                        std::net::IpAddr::V4(_) => (
                            libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize,
                            libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32)
                                as usize,
                        ),
                        std::net::IpAddr::V6(_) => (
                            libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as u32)
                                as usize,
                            libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32)
                                as usize,
                        ),
                    };
                    hdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
                    hdr.msg_controllen = pktinfo_space;

                    let cmsg = libc::CMSG_FIRSTHDR(hdr);
                    if !cmsg.is_null() {
                        match local_ip {
                            std::net::IpAddr::V4(v4) => {
                                (*cmsg).cmsg_level = libc::IPPROTO_IP;
                                (*cmsg).cmsg_type = libc::IP_PKTINFO;
                                (*cmsg).cmsg_len = pktinfo_len;
                                // `send_ifindex` is always 0 on IPv4: per ip(7), a
                                // nonzero ifindex makes the kernel prefer the
                                // interface's primary address over ipi_spec_dst on
                                // multi-IP interfaces, which would defeat the
                                // "reply from captured destination" semantics.
                                // ipi_spec_dst alone is sufficient on IPv4.
                                let pi = libc::in_pktinfo {
                                    ipi_ifindex: send_ifindex as libc::c_int,
                                    ipi_spec_dst: libc::in_addr {
                                        s_addr: u32::from(v4).to_be(),
                                    },
                                    ipi_addr: libc::in_addr { s_addr: 0 },
                                };
                                std::ptr::copy_nonoverlapping(
                                    &pi as *const libc::in_pktinfo as *const u8,
                                    libc::CMSG_DATA(cmsg),
                                    std::mem::size_of::<libc::in_pktinfo>(),
                                );
                            }
                            std::net::IpAddr::V6(v6) => {
                                (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                                (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                                (*cmsg).cmsg_len = pktinfo_len;
                                let pi = libc::in6_pktinfo {
                                    ipi6_addr: libc::in6_addr {
                                        s6_addr: v6.octets(),
                                    },
                                    ipi6_ifindex: send_ifindex,
                                };
                                std::ptr::copy_nonoverlapping(
                                    &pi as *const libc::in6_pktinfo as *const u8,
                                    libc::CMSG_DATA(cmsg),
                                    std::mem::size_of::<libc::in6_pktinfo>(),
                                );
                            }
                        }
                    }
                }
            }
        }

        let ret = unsafe {
            libc::sendmmsg(
                fd,
                msgs_base,
                self.count as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            #[cfg(feature = "bench-udp-profile")]
            crate::udp_profile::sendmmsg(
                self.profile_direction,
                self.count,
                &Err(err.kind().into()),
                0,
            );
            // Clear the batch on error — UDP is best-effort and preserving
            // stale datagrams would cause reorder/requeue across iterations.
            // (GsoBatchBuf preserves on error because it has drain_to_sendmmsg
            // fallback; SendMmsgBatch is the final send path with no fallback.)
            self.count = 0;
            return Err(err);
        }

        let sent = ret as usize;
        let sent_bytes = self.lens.iter().take(sent).sum();
        #[cfg(feature = "bench-udp-profile")]
        crate::udp_profile::sendmmsg(self.profile_direction, self.count, &Ok(sent), sent_bytes);
        let remaining = self.count - sent;
        if remaining > 0 {
            // Shift unsent datagrams to the front so a retry sends them.
            for i in 0..remaining {
                self.bufs.swap(i, sent + i);
                self.lens[i] = self.lens[sent + i];
                self.dest_addrs[i] = self.dest_addrs[sent + i];
                self.dest_addr_lens[i] = self.dest_addr_lens[sent + i];
                self.local_ips[i] = self.local_ips[sent + i];
            }
        }
        self.count = remaining;
        Ok(SendMmsgFlush {
            datagrams: sent,
            bytes: sent_bytes,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod sendmmsg_batch_tests {
    use std::net::SocketAddr;

    use super::{SendMmsgBatch, SendMmsgPushResult};

    #[test]
    fn pending_stats_reports_queued_datagrams_and_bytes() {
        let mut batch = SendMmsgBatch::new(4);
        let dest: SocketAddr = "127.0.0.1:5353".parse().expect("valid socket addr");

        assert_eq!(batch.pending_stats().datagrams, 0);
        assert_eq!(
            batch.push_with_local(b"abc", dest, None),
            SendMmsgPushResult::Queued
        );
        assert_eq!(
            batch.push_with_local(b"de", dest, None),
            SendMmsgPushResult::Queued
        );

        let stats = batch.pending_stats();
        assert_eq!(stats.datagrams, 2);
        assert_eq!(stats.bytes, 5);
    }
}

/// Convert a `std::net::SocketAddr` to `libc::sockaddr_storage` + length.
///
/// `pub(crate)` so `flush_gso_batch()` in `udp_proxy.rs` and the DTLS server's
/// pinned reply-source send path (`crate::dtls`) can both call it directly
/// without a wrapper — one conversion, so the two datagram frontends cannot
/// disagree about destination encoding.
#[cfg(target_os = "linux")]
pub(crate) fn std_to_sockaddr_storage(
    addr: SocketAddr,
) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*v4.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_in fits within sockaddr_storage.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin as *const libc::sockaddr_in as *const u8,
                    &mut storage as *mut libc::sockaddr_storage as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin6 as *const libc::sockaddr_in6 as *const u8,
                    &mut storage as *mut libc::sockaddr_storage as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

/// GSO batch buffer for sending multiple same-size datagrams in a single `sendmsg()`
/// with `UDP_SEGMENT` ancillary data (Linux 4.18+).
///
/// Concatenates consecutive same-size datagrams into a contiguous buffer and flushes
/// via `send_with_gso()`. When a different-size datagram
/// arrives, the current batch is flushed and a new batch starts. This is complementary
/// to `SendMmsgBatch` — GSO provides kernel-level segmentation which is more efficient
/// than `sendmmsg` when datagrams share the same size and destination.
///
/// Only available on Linux. On other platforms, the UDP proxy falls back to `SendMmsgBatch`
/// or individual sends.
#[cfg(target_os = "linux")]
pub struct GsoBatchBuf {
    #[cfg(feature = "bench-udp-profile")]
    pub profile_direction: crate::udp_profile::Direction,
    /// Contiguous buffer holding concatenated same-size datagrams.
    buf: Vec<u8>,
    /// Segment size of datagrams currently in the buffer (0 = empty).
    segment_size: usize,
    /// Number of datagrams currently in the buffer.
    count: usize,
    /// Maximum bytes to accumulate before auto-flushing.
    /// Kernel GSO limit is typically 64KB (~65535 bytes).
    max_bytes: usize,
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
impl GsoBatchBuf {
    /// Create a new GSO batch buffer.
    ///
    /// `max_bytes` caps the concatenated buffer size. The kernel GSO path
    /// has a ~64KB limit per sendmsg, so 65535 is a safe maximum.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            #[cfg(feature = "bench-udp-profile")]
            profile_direction: crate::udp_profile::Direction::Other,
            buf: Vec::with_capacity(max_bytes.min(65535)),
            segment_size: 0,
            count: 0,
            max_bytes: max_bytes.min(65535),
        }
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Count and byte volume of datagrams currently queued in this GSO batch.
    pub fn pending_stats(&self) -> SendMmsgFlush {
        SendMmsgFlush {
            datagrams: self.count,
            bytes: self.buf.len(),
        }
    }

    /// Drop every queued datagram without sending.
    ///
    /// Allocation-free: the concatenated buffer keeps its capacity for reuse.
    /// After discard the buffer is empty, so a subsequent [`Self::flush_to`]
    /// is a no-op — discarded payloads must not be counted as sent.
    pub fn discard(&mut self) {
        #[cfg(feature = "bench-udp-profile")]
        {
            crate::udp_profile::batch_count(
                self.profile_direction,
                BatchField::GsoDiscardedSegments,
                self.count,
            );
            crate::udp_profile::batch_count(
                self.profile_direction,
                BatchField::GsoDiscardedBytes,
                self.buf.len(),
            );
        }
        self.buf.clear();
        self.count = 0;
        self.segment_size = 0;
    }

    /// Try to append a datagram. Returns `false` if the datagram has a different
    /// size than the current batch or the buffer would exceed `max_bytes`, meaning
    /// the caller should flush first and then call `push` again.
    pub fn push(&mut self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        if self.count == 0 {
            // First datagram — set segment size.
            self.segment_size = data.len();
            self.buf.clear();
            self.buf.extend_from_slice(data);
            self.count = 1;
            return true;
        }
        // Same size check: GSO requires all segments to be the same size
        // (the last segment may be shorter, but we only batch exact matches
        // for simplicity and correctness).
        if data.len() != self.segment_size {
            return false; // different size — caller should flush first
        }
        if self.buf.len() + data.len() > self.max_bytes {
            return false; // would exceed max — caller should flush first
        }
        self.buf.extend_from_slice(data);
        self.count += 1;
        true
    }

    /// Flush the buffer via GSO sendmsg to a specific destination address.
    ///
    /// When `local_ip` is `Some`, an IP(v6)_PKTINFO cmsg is attached alongside
    /// the UDP_SEGMENT (GSO) cmsg in a single sendmsg call — this gives the
    /// kernel the reply source address directly and saves one routing-table
    /// lookup per flush. When `None`, the legacy `send_with_gso` path is used.
    pub fn flush_to(
        &mut self,
        fd: std::os::fd::RawFd,
        dest: &libc::sockaddr_storage,
        dest_len: libc::socklen_t,
        local: Option<crate::socket_opts::PktinfoLocal>,
    ) -> std::io::Result<usize> {
        if self.count == 0 {
            return Ok(0);
        }
        // Avoid attaching a UDP_SEGMENT (GSO) cmsg when flushing a single
        // datagram: there is nothing for the kernel to segment, so passing
        // `None` skips `udp_cmsg_send` and GSO skb setup on the kernel side.
        let gso_seg = (self.count > 1).then_some(self.segment_size as u16);
        let result = if let Some(local) = local {
            crate::socket_opts::send_with_pktinfo(fd, &self.buf, local, dest, dest_len, gso_seg)
        } else if let Some(seg) = gso_seg {
            crate::socket_opts::send_with_gso(fd, &self.buf, seg, dest, dest_len)
        } else {
            crate::socket_opts::send_with_prebuilt_pktinfo(fd, &self.buf, dest, dest_len, None)
        };
        #[cfg(feature = "bench-udp-profile")]
        crate::udp_profile::gso(
            self.profile_direction,
            self.count,
            self.buf.len(),
            self.segment_size,
            &result,
        );
        let sent_count = self.count;
        // Only clear on success — on failure, the buffer is preserved so
        // drain_to_sendmmsg() can replay the datagrams through sendmmsg.
        if result.is_ok() {
            self.buf.clear();
            self.count = 0;
            self.segment_size = 0;
        }
        result.map(|_| sent_count)
    }

    /// Drain buffered datagrams into a `SendMmsgBatch` for fallback sending.
    ///
    /// Splits the contiguous GSO buffer back into individual datagrams by
    /// `segment_size` and pushes each into the sendmmsg batch. Stops early
    /// when the sendmmsg batch is full or when a segment exceeds the sendmmsg
    /// slot size (`SendMmsgPushResult::Oversized`); remaining datagrams stay
    /// in the GSO buffer. For the oversized case the caller should
    /// [`Self::take_front_datagram`] and direct-send, then continue draining.
    /// Returns the number of datagrams drained.
    pub fn drain_to_sendmmsg(
        &mut self,
        send_batch: &mut SendMmsgBatch,
        dest: std::net::SocketAddr,
        local: Option<crate::socket_opts::PktinfoLocal>,
    ) -> usize {
        if self.count == 0 || self.segment_size == 0 {
            return 0;
        }
        let mut offset = 0;
        let mut drained = 0;
        while offset < self.buf.len() {
            let end = (offset + self.segment_size).min(self.buf.len());
            match send_batch.push_with_local(&self.buf[offset..end], dest, local) {
                SendMmsgPushResult::Queued => {
                    offset = end;
                    drained += 1;
                }
                SendMmsgPushResult::Full | SendMmsgPushResult::Oversized => {
                    break; // remaining stays in GSO buffer
                }
            }
        }
        if offset >= self.buf.len() {
            // All datagrams drained — clear the buffer.
            self.buf.clear();
            self.count = 0;
            self.segment_size = 0;
        } else {
            // Partial drain — shift remaining data to the front.
            self.buf.drain(..offset);
            self.count -= drained;
        }
        #[cfg(feature = "bench-udp-profile")]
        crate::udp_profile::batch_count(
            self.profile_direction,
            BatchField::GsoFallbackToMmsgSegments,
            drained,
        );
        drained
    }

    /// Remove and return the front datagram (one `segment_size` slice).
    ///
    /// Used when `drain_to_sendmmsg` stops on `SendMmsgPushResult::Oversized`
    /// so the UDP reply path can direct-send the segment and continue. Returns
    /// `None` when the buffer is empty.
    pub fn take_front_datagram(&mut self) -> Option<Vec<u8>> {
        if self.count == 0 || self.segment_size == 0 || self.buf.is_empty() {
            return None;
        }
        let end = self.segment_size.min(self.buf.len());
        let dgram = self.buf[..end].to_vec();
        self.buf.drain(..end);
        self.count -= 1;
        if self.count == 0 || self.buf.is_empty() {
            self.buf.clear();
            self.count = 0;
            self.segment_size = 0;
        }
        #[cfg(feature = "bench-udp-profile")]
        crate::udp_profile::batch_count(
            self.profile_direction,
            BatchField::GsoFallbackDirectSegments,
            1,
        );
        Some(dgram)
    }
}
