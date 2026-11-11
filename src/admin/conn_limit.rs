//! Admin listener connection limiting.
//!
//! The proxy data-plane accept loop is bounded by `FERRUM_MAX_CONNECTIONS`
//! (a semaphore sized at config load) plus the overload manager's
//! `reject_new_connections` flag. The admin/management-plane accept loops
//! (`serve_admin_on_listener` / `serve_admin_on_listener_with_dynamic_tls`)
//! historically had **no** equivalent: every accepted TCP connection was
//! handed to an unbounded `tokio::spawn`, so the only ceiling on concurrent
//! admin connections (each costing a file descriptor + a task + a pending TLS
//! handshake / header-read buffer) was the OS file-descriptor limit.
//!
//! [`AdminConnLimiter`] closes that gap with a dedicated, management-plane
//! connection cap that is independent of the data-plane `FERRUM_MAX_CONNECTIONS`
//! knob, so operators can size proxy traffic and admin traffic separately.
//!
//! Enforcement happens in the accept loop **after** the CIDR allowlist check
//! and **before** the per-connection task is spawned (i.e. before the TLS
//! handshake or any HTTP header parsing). Over-limit connections are dropped
//! immediately (TCP RST) with zero task overhead, mirroring the data-plane
//! accept loop's behaviour — at the pre-TLS/pre-HTTP point there is no
//! negotiated protocol state on which to return a clean 503.
//!
//! The acquired [`AdminConnPermit`] is held for the connection's entire
//! lifetime (it is moved into the spawned task) and releases the global slot +
//! per-IP slot on drop, so the cap tracks the real concurrency driver.
//!
//! The mechanism itself lives in [`crate::util::conn_limit`], shared with the
//! CP gRPC listener's pre-authentication admission gate (advisory
//! GHSA-2xqr-7j7p-77qp) so both surfaces have identical lifecycle, per-IP
//! cardinality, and rejection-accounting behaviour. These names are the
//! admin-facing spelling of that primitive.

pub use crate::util::conn_limit::{
    ConnLimiter as AdminConnLimiter, ConnLimiterSnapshot as AdminConnLimiterSnapshot,
    ConnPermit as AdminConnPermit, ConnRejectReason as AdminConnRejectReason,
};
