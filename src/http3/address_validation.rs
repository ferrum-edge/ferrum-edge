//! QUIC source-address validation for the HTTP/3 frontend listener.
//!
//! A QUIC Initial arrives over UDP, so its source address is unauthenticated:
//! an off-path sender can forge any address. Until the peer proves it can
//! receive packets at that address (RFC 9000 §8.1) — by echoing a Retry token
//! or presenting a NEW_TOKEN token from an earlier connection — every
//! handshake the listener runs for it is state and TLS work the sender never
//! has to pay for.
//!
//! The listener therefore keeps a dedicated, bounded budget for handshakes from
//! unvalidated sources ([`UnvalidatedHandshakeBudget`],
//! `FERRUM_HTTP3_MAX_UNVALIDATED_HANDSHAKES`). Such handshakes hold a permit
//! from that budget instead of a slot in the shared overload connection budget
//! (`OverloadState::active_connections`), and are charged to the shared budget
//! only once the handshake completes. When the budget is full, further
//! unvalidated Initials are answered with a stateless Retry, which costs the
//! listener no connection state and no TLS work; a genuine client echoes the
//! token and is admitted as validated. `0` sends a Retry to every unvalidated
//! source.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Default `FERRUM_HTTP3_MAX_UNVALIDATED_HANDSHAKES`.
pub const H3_MAX_UNVALIDATED_HANDSHAKES_DEFAULT: usize = 1024;

/// Per-listener budget of in-flight handshakes from source addresses that have
/// not been validated.
#[derive(Debug)]
pub struct UnvalidatedHandshakeBudget {
    limit: usize,
    in_flight: AtomicUsize,
}

impl UnvalidatedHandshakeBudget {
    /// A budget admitting at most `limit` concurrent unvalidated handshakes.
    /// `0` admits none, so every unvalidated source is sent a Retry.
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            in_flight: AtomicUsize::new(0),
        })
    }

    /// The configured ceiling.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Unvalidated handshakes currently holding a permit.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Take one permit, or `None` when the budget is exhausted. The permit is
    /// returned to the budget when it drops.
    pub fn try_acquire(self: &Arc<Self>) -> Option<UnvalidatedHandshakePermit> {
        self.in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.limit).then_some(current + 1)
            })
            .ok()?;
        Some(UnvalidatedHandshakePermit {
            budget: Arc::clone(self),
        })
    }
}

/// One in-flight unvalidated handshake. Dropping it releases the slot.
#[derive(Debug)]
pub struct UnvalidatedHandshakePermit {
    budget: Arc<UnvalidatedHandshakeBudget>,
}

impl Drop for UnvalidatedHandshakePermit {
    fn drop(&mut self) {
        self.budget.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// What the listener does with one QUIC `Incoming`.
#[derive(Debug)]
pub enum IncomingAdmission {
    /// The source address is validated (Retry or NEW_TOKEN token): accept and
    /// charge the shared connection budget from the start.
    Validated,
    /// Unvalidated, but within the handshake budget: accept while holding the
    /// permit, and charge the shared connection budget only once the
    /// handshake completes.
    Unvalidated(UnvalidatedHandshakePermit),
    /// Unvalidated and over budget: answer with a stateless Retry.
    Retry,
    /// Unvalidated, over budget, and a Retry is not permitted (the Initial
    /// already followed one): refuse without running a handshake.
    Refuse,
}

/// Decide how to admit one QUIC `Incoming` from its address-validation state.
pub fn classify_incoming(
    remote_address_validated: bool,
    may_retry: bool,
    budget: &Arc<UnvalidatedHandshakeBudget>,
) -> IncomingAdmission {
    if remote_address_validated {
        return IncomingAdmission::Validated;
    }
    match budget.try_acquire() {
        Some(permit) => IncomingAdmission::Unvalidated(permit),
        None if may_retry => IncomingAdmission::Retry,
        None => IncomingAdmission::Refuse,
    }
}
