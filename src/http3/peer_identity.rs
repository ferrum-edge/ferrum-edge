//! Per-connection HTTP/3 peer-identity snapshot.
//!
//! A QUIC connection's peer certificate is only knowable once the TLS 1.3
//! handshake has completed. When 0-RTT is enabled the gateway materializes the
//! `quinn::Connection` at 0.5-RTT — *before* the client's `Certificate` /
//! `Finished` flight has arrived — so reading `Connection::peer_identity()`
//! at that moment always yields `None`. Pinning that pre-handshake `None` for
//! the lifetime of the connection silently disabled frontend H3 mTLS for every
//! request on every H3 connection (issue #2938).
//!
//! This module owns the three halves of the fix:
//!
//! 1. [`zero_rtt_admitted`] — the admission decision. A listener configured
//!    with a frontend client-certificate verifier never takes quinn's
//!    `into_0rtt()` path at all and sets the QUIC TLS early-data size to zero.
//!    Incoming 0.5-RTT precedes client authentication, so materializing the
//!    connection there would create a pre-handshake identity window.
//! 2. [`H3ConnectionIdentity`] — a lock-free, per-connection `ArcSwap` slot
//!    holding one coherent [`H3PeerIdentity`] snapshot. Requests read the whole
//!    snapshot with a single `load_full()`, so `is_early_data` and the peer
//!    certificate can never be observed out of step with each other. The slot
//!    starts at [`H3PeerIdentity::pre_handshake`] (early data, **no** identity)
//!    and is republished exactly once, after a successful handshake, with the
//!    identity quinn then reports.
//! 3. [`ZeroRttCompletion`] — the accept loop's own view of quinn's
//!    handshake-completion signal. Each request stream is classified from the
//!    handshake state the accept loop observes right after accepting it
//!    (issue #5761): [`H3ConnectionIdentity::accepted_stream_snapshot`]
//!    re-reads the signal without waiting, so a 1-RTT request that arrives in
//!    the same flight as the client's `Finished` can never be classified as
//!    early data merely because the completion wake-up had not been scheduled
//!    yet. A 0-RTT stream can still be classified 1-RTT when the handshake
//!    completed before that re-read; [`ZeroRttCompletion`] explains why that
//!    relaxation is safe (RFC 8470 §6.2).
//!
//! The rules that make this fail-closed:
//!
//! - An identity-bearing snapshot is only ever produced by
//!   [`H3PeerIdentity::established`], which hard-codes `is_early_data = false`.
//!   A request can therefore never be treated as authenticated early data.
//! - The slot only leaves the pre-handshake state after quinn reported that
//!   the handshake reached `Connected` on a still-open connection. A stream the
//!   accept loop took while that signal was still pending was necessarily
//!   opened by 0-RTT packets (quinn does not process 1-RTT packets before the
//!   handshake completes) and stays early data for its whole life.
//! - A slot is created per connection and is never shared between connections,
//!   so a handshake that fails, times out, or is cancelled simply leaves its
//!   own slot at the pre-handshake snapshot. No other connection's identity can
//!   leak into it.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use arc_swap::ArcSwap;

use crate::plugins::mesh::spiffe_identity::SpiffeIdentityConnectionCache;
use crate::plugins::mtls_auth::MtlsAuthConnectionCache;

/// Whether the HTTP/3 listener may use quinn's `into_0rtt()` 0.5-RTT accept
/// path for a connection.
///
/// 0-RTT requires the operator to have opted in via
/// `FERRUM_TLS_EARLY_DATA_METHODS`, **and** requires the listener not to be
/// doing frontend client-certificate authentication. Taking the 0.5-RTT path
/// under client auth would materialize the connection before the peer's
/// certificate is known.
#[inline]
pub fn zero_rtt_admitted(
    early_data_methods_configured: bool,
    client_auth_configured: bool,
) -> bool {
    early_data_methods_configured && !client_auth_configured
}

/// QUIC rustls `max_early_data_size` for the listener posture.
///
/// Quinn accepts only `0` or `u32::MAX`. Keep the TLS advertisement coupled to
/// [`zero_rtt_admitted`]: an mTLS listener must disable early data in the TLS
/// configuration as well as refusing the 0.5-RTT application accept path.
/// Otherwise a stateful-resumption fallback could accept replayable client
/// early data and deliver it only after the full handshake, where the request
/// loop would no longer be able to distinguish it from ordinary 1-RTT data.
#[inline]
pub fn quic_max_early_data_size(
    early_data_methods_configured: bool,
    client_auth_configured: bool,
) -> u32 {
    if zero_rtt_admitted(early_data_methods_configured, client_auth_configured) {
        u32::MAX
    } else {
        0
    }
}

/// Convert quinn's server-side `ZeroRttAccepted` completion into a handshake
/// success decision.
///
/// The future resolves when the handshake reaches `Connected`, but its boolean
/// only reports whether 0-RTT data was accepted and is documented as
/// meaningless on servers. A successful server handshake can therefore report
/// `false` when the client sent no early data. When the resolved future is
/// observed, an open connection proves the handshake completed; on quinn's
/// failure path `close_reason()` is already populated before the receiver is
/// completed. Retaining a `true` acceptance result also handles a peer closing
/// immediately after a successful 0-RTT handshake.
#[inline]
pub fn server_0rtt_handshake_succeeded(zero_rtt_accepted: bool, connection_is_open: bool) -> bool {
    zero_rtt_accepted || connection_is_open
}

/// The HTTP/3 accept loop's handle on a 0.5-RTT connection's
/// handshake-completion signal (quinn's server-side `ZeroRttAccepted`).
///
/// The accept loop owns this directly instead of hearing about completion from
/// a separate task. Quinn's connection driver moves the handshake to
/// `Connected` and fires this signal within one hold of the connection-state
/// lock, and `accept_bi` takes that same lock. So once a request stream has
/// been accepted, one non-blocking poll here that still finds the signal
/// pending proves quinn handed the stream out mid-handshake, which quinn also
/// records for that stream as `RecvStream::is_0rtt()`. Quinn drops 1-RTT
/// packets until the handshake completes, so such a stream was opened by 0-RTT
/// data. A stream opened by 1-RTT data always finds the signal fired.
/// Relaying the signal through a spawned task (the pre-#5761 design) added a
/// scheduler hop, so a 1-RTT request arriving in the same flight as the
/// client's `Finished` could be accepted before the relayed signal and wrongly
/// classified as early data.
///
/// Only that one direction holds: "signal pending at the re-poll" implies
/// `is_0rtt()`, not the reverse. A stream quinn marks as 0-RTT is classified
/// 1-RTT when the handshake completes before the re-poll: between quinn
/// accepting the stream and the re-poll, for 0-RTT streams still queued in
/// quinn when the handshake completed, and for reordered 0-RTT packets that
/// open a stream after the client's `Finished`. That relaxation is deliberate.
/// A replay can never complete a handshake (it lacks the client's keys), so
/// every replayed copy stays early data and is refused or forwarded with
/// `Early-Data: 1` by whichever instance receives it. The operative rule is
/// RFC 8470 §6.4, which permits processing early data received after the
/// handshake completes. §6.2 is still satisfied, because processing after
/// completion is the "delay" treatment it permits, and replays stay early.
///
/// The inner future is polled only while pending and dropped as soon as it
/// resolves, so it is never polled after completion. No lock and no
/// allocation: polling a oneshot receiver is an atomic state check.
pub struct ZeroRttCompletion<F> {
    pending: Option<F>,
}

impl<F> ZeroRttCompletion<F>
where
    F: Future<Output = bool> + Unpin,
{
    /// Track a handshake that has not completed yet (the 0.5-RTT accept path).
    pub fn pending(completion: F) -> Self {
        Self {
            pending: Some(completion),
        }
    }

    /// Nothing to track: the handshake completed before the accept loop
    /// started (every full-handshake accept path).
    pub fn resolved() -> Self {
        Self { pending: None }
    }

    /// Whether the completion signal has not been observed yet.
    #[inline]
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Poll the completion signal. Yields the signal's value exactly once and
    /// stays `Pending` forever afterwards (and when nothing is tracked), so it
    /// can sit in a `select!` branch guarded by [`Self::is_pending`].
    pub fn poll_outcome(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        let Some(completion) = self.pending.as_mut() else {
            return Poll::Pending;
        };
        match Pin::new(completion).poll(cx) {
            Poll::Ready(zero_rtt_accepted) => {
                self.pending = None;
                Poll::Ready(zero_rtt_accepted)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Wait for the completion signal.
    pub fn outcome(&mut self) -> impl Future<Output = bool> + '_ {
        std::future::poll_fn(move |cx| self.poll_outcome(cx))
    }

    /// Observe the completion signal without waiting: `Some(value)` if it has
    /// fired and was not observed before, `None` otherwise.
    ///
    /// Polled outside tokio's cooperative budget. Quinn's signal is a tokio
    /// oneshot receiver, which reports `Pending` once the task has spent its
    /// budget even when the value is already there. Inside the budget, a busy
    /// accept loop would read an already-fired signal as pending and classify
    /// a 1-RTT stream as early data.
    pub async fn observe_now(&mut self) -> Option<bool> {
        let observe = std::future::poll_fn(|cx| match self.poll_outcome(cx) {
            Poll::Ready(zero_rtt_accepted) => Poll::Ready(Some(zero_rtt_accepted)),
            Poll::Pending => Poll::Ready(None),
        });
        tokio::task::unconstrained(observe).await
    }
}

/// One coherent view of an HTTP/3 connection's peer identity, published as a
/// unit so a request stream cannot mix an early-data flag from one point in the
/// connection lifecycle with a certificate from another.
#[derive(Debug, Default)]
pub struct H3PeerIdentity {
    /// True only while the connection is still inside the 0.5-RTT window (the
    /// TLS handshake had not completed when the request stream was accepted).
    /// Requests snapshotting this value are early data: method-gated by
    /// `FERRUM_TLS_EARLY_DATA_METHODS` and marked `Early-Data: 1` toward the
    /// backend (RFC 8470).
    pub is_early_data: bool,
    /// Peer leaf certificate DER, when the peer authenticated.
    pub client_cert_der: Option<Arc<Vec<u8>>>,
    /// Intermediate/CA certificates (index 1+) for per-proxy CA filtering in
    /// `mtls_auth`.
    pub client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
    /// Connection-scoped `mtls_auth` evaluation cache. Present only when a peer
    /// certificate is present, so it can never be reused across an identity
    /// change.
    pub mtls_auth_connection_cache: Option<Arc<MtlsAuthConnectionCache>>,
    /// Connection-scoped SPIFFE extraction cache, present under the same
    /// condition as `mtls_auth_connection_cache`.
    pub peer_spiffe_extraction_cache: Option<Arc<SpiffeIdentityConnectionCache>>,
}

impl H3PeerIdentity {
    /// The pre-handshake snapshot: requests are early data and **no** peer
    /// identity is exposed. This is the only snapshot with
    /// `is_early_data == true`, and it deliberately carries no certificate,
    /// chain, or cache.
    pub fn pre_handshake() -> Self {
        Self {
            is_early_data: true,
            ..Self::default()
        }
    }

    /// The post-handshake snapshot built from the certificate chain quinn
    /// reports once the TLS handshake has completed. `is_early_data` is always
    /// `false` here — an identity-bearing snapshot is by construction not early
    /// data.
    pub fn established(peer_certs: Option<Vec<Vec<u8>>>) -> Self {
        let client_cert_der: Option<Arc<Vec<u8>>> = peer_certs
            .as_ref()
            .and_then(|certs| certs.first())
            .map(|cert| Arc::new(cert.clone()));
        let client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>> = peer_certs
            .as_ref()
            .filter(|certs| certs.len() > 1)
            .map(|certs| Arc::new(certs[1..].to_vec()));
        // The peer cert is fixed for the connection once the handshake
        // completes, so both caches derive their outcome once and every
        // multiplexed request stream reuses it. Allocated only alongside a
        // real certificate.
        let mtls_auth_connection_cache = client_cert_der
            .as_ref()
            .map(|_| Arc::new(MtlsAuthConnectionCache::new()));
        let peer_spiffe_extraction_cache = client_cert_der
            .as_ref()
            .map(|_| Arc::new(SpiffeIdentityConnectionCache::new()));
        Self {
            is_early_data: false,
            client_cert_der,
            client_cert_chain_der,
            mtls_auth_connection_cache,
            peer_spiffe_extraction_cache,
        }
    }
}

/// Per-connection, lock-free holder for the current [`H3PeerIdentity`].
///
/// The accept loop performs one `ArcSwap::load_full()` per accepted request
/// stream — no lock, no allocation beyond the `Arc` refcount bump it already
/// paid when cloning the per-request certificate handles.
#[derive(Debug)]
pub struct H3ConnectionIdentity {
    slot: ArcSwap<H3PeerIdentity>,
}

impl H3ConnectionIdentity {
    /// Create a slot in the pre-handshake state (0.5-RTT window, no identity).
    pub fn pre_handshake() -> Self {
        Self {
            slot: ArcSwap::from_pointee(H3PeerIdentity::pre_handshake()),
        }
    }

    /// Publish the post-handshake identity after a successful handshake,
    /// atomically clearing the early-data flag in the same swap.
    ///
    /// Called exactly once per connection: from the accept path itself on the
    /// ordinary full-handshake branches (where the connection future only
    /// resolves after the peer's `Finished` has been processed, and before any
    /// request stream can be accepted), or — through
    /// [`Self::publish_zero_rtt_completion`] — from the 0.5-RTT accept loop
    /// once it observes quinn's `ZeroRttAccepted` signal. The signal's boolean
    /// is not itself a server handshake-success signal;
    /// [`server_0rtt_handshake_succeeded`] combines it with connection state. A
    /// failed connection must keep the pre-handshake snapshot so buffered early
    /// data cannot lose replay gating.
    pub fn publish_handshake_result(
        &self,
        handshake_succeeded: bool,
        peer_certs: Option<Vec<Vec<u8>>>,
    ) {
        if !handshake_succeeded {
            return;
        }
        let established = Arc::new(H3PeerIdentity::established(peer_certs));
        let current = self.slot.load_full();
        if !current.is_early_data {
            return;
        }
        // Enforce the documented one-publication lifecycle in the holder
        // itself. If a future refactor accidentally creates two publishers,
        // only the first transition from the unique pre-handshake snapshot can
        // win; a later certificate can never replace the identity and caches
        // already shared with multiplexed request contexts.
        let _previous = self.slot.compare_and_swap(&current, established);
    }

    /// Publish the outcome of an observed 0.5-RTT handshake-completion signal.
    ///
    /// `connection_is_open` is read at observation time; `peer_certs` is only
    /// consulted when the handshake succeeded. Returns whether it succeeded.
    pub fn publish_zero_rtt_completion(
        &self,
        zero_rtt_accepted: bool,
        connection_is_open: bool,
        peer_certs: impl FnOnce() -> Option<Vec<Vec<u8>>>,
    ) -> bool {
        let handshake_succeeded =
            server_0rtt_handshake_succeeded(zero_rtt_accepted, connection_is_open);
        let peer_certs = if handshake_succeeded {
            peer_certs()
        } else {
            None
        };
        self.publish_handshake_result(handshake_succeeded, peer_certs);
        handshake_succeeded
    }

    /// The snapshot for a request stream the accept loop has **just**
    /// accepted (issue #5761).
    ///
    /// Before reading the slot, observe the handshake-completion signal once
    /// without waiting. If quinn completed the handshake before it handed out
    /// this stream, the signal has already fired (see [`ZeroRttCompletion`]),
    /// so the established identity is published first and the stream is
    /// classified as 1-RTT — even when the accept loop had not yet been woken
    /// for the completion. If the signal is still pending, the handshake was
    /// still in progress when quinn accepted the stream, which means the stream
    /// was opened by 0-RTT packets: it keeps the pre-handshake (early data,
    /// no identity) snapshot. The converse does not hold: a 0-RTT stream is
    /// classified 1-RTT when the handshake completed before this re-poll (see
    /// [`ZeroRttCompletion`] for why that is safe). On a connection whose
    /// handshake completed before the accept loop started this is one
    /// lock-free load.
    pub async fn accepted_stream_snapshot<F>(
        &self,
        completion: &mut ZeroRttCompletion<F>,
        connection_is_open: impl FnOnce() -> bool,
        peer_certs: impl FnOnce() -> Option<Vec<Vec<u8>>>,
    ) -> Arc<H3PeerIdentity>
    where
        F: Future<Output = bool> + Unpin,
    {
        if completion.is_pending()
            && let Some(zero_rtt_accepted) = completion.observe_now().await
        {
            self.publish_zero_rtt_completion(zero_rtt_accepted, connection_is_open(), peer_certs);
        }
        self.snapshot()
    }

    /// Read the current snapshot. One lock-free load; every field a request
    /// uses comes from this single consistent view.
    #[inline]
    pub fn snapshot(&self) -> Arc<H3PeerIdentity> {
        self.slot.load_full()
    }
}
