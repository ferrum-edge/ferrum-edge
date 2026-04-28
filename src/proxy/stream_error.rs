//! Typed error infrastructure for stream-family (TCP/UDP/DTLS/WebSocket-tunnel) proxies.
//!
//! Replaces the legacy "shared error-message prefix" pattern (where
//! [`crate::proxy::tcp_proxy::pre_copy_disconnect_cause`] and
//! [`crate::proxy::udp_proxy::dtls_disconnect_cause`] inferred client/backend
//! attribution by `.contains()`-matching on `STREAM_ERR_*` prefixes embedded
//! in the error's Display string).
//!
//! Now construction sites build a [`StreamSetupError`] carrying a typed
//! [`StreamSetupKind`]. The cause mappers walk the [`anyhow::Error`] source
//! chain via `downcast_ref::<StreamSetupError>()` to read the kind directly —
//! no substring matching, no risk of wording drift between the construction
//! site and the consumer.
//!
//! The Display impl reproduces the legacy `STREAM_ERR_*` prefix so log lines
//! and `StreamTransactionSummary.connection_error` strings are
//! byte-for-byte unchanged for operators and downstream pipelines.

use std::fmt;

/// Which side of a TLS/DTLS handshake failed.
///
/// Used by stream-family disconnect-cause mappers to attribute a
/// [`crate::retry::ErrorClass::TlsError`] to the client or backend without
/// substring-matching the error message. Returned by
/// [`StreamSetupKind::tls_side`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsErrorSide {
    /// Frontend TLS termination: the gateway accepted a client connection and
    /// the rustls/tokio-rustls handshake failed.
    Frontend,
    /// Backend TLS or DTLS origination: the gateway dialed a backend and the
    /// outbound TLS/DTLS handshake failed.
    Backend,
}

/// Typed kind for a stream-family setup failure.
///
/// Each variant corresponds to a specific construction site in the TCP/UDP
/// proxies — the kind alone tells the cause mapper whether the failure was
/// client-side ([`crate::plugins::DisconnectCause::RecvError`]) or
/// backend-side ([`crate::plugins::DisconnectCause::BackendError`]) without
/// inspecting the message string.
///
/// **Adding new variants**: only when a NEW construction site needs explicit
/// client/backend attribution that isn't covered by the existing kinds.
/// `RejectedByPlugin` is the umbrella for any `on_stream_connect` /
/// `before_proxy` rejection (ACL, policy, rate-limit, etc.) since they all
/// classify identically (client-side, RecvError); split it only if a future
/// consumer needs to distinguish them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSetupKind {
    /// Frontend TLS handshake (client → gateway) failed. Client-side: the
    /// client either presented an invalid certificate, negotiated an
    /// incompatible cipher suite, or reset mid-handshake.
    FrontendTlsHandshake,
    /// Backend TLS handshake (gateway → backend) failed for a `tcp_tls`
    /// proxy.
    BackendTlsHandshake,
    /// Backend DTLS handshake (gateway → backend) failed for a `dtls`
    /// proxy.
    BackendDtlsHandshake,
    /// Connection or session was rejected by a stream-lifecycle plugin
    /// (`on_stream_connect`/`before_proxy`). Covers ACL/policy/throttle
    /// rejections — they all share the same client-side classification.
    RejectedByPlugin,
    /// Load balancer returned no healthy targets for the configured upstream.
    /// Backend-side — the configured pool is empty or all targets are
    /// circuit-broken.
    NoHealthyTargets,
}

impl StreamSetupKind {
    /// If this kind represents a TLS/DTLS handshake failure, return which
    /// side handshook. `None` for non-TLS kinds.
    ///
    /// Used by [`Self::is_client_side`] (TLS-frontend → client side) so
    /// callers can also introspect the side directly without re-deriving
    /// the relationship.
    pub fn tls_side(self) -> Option<TlsErrorSide> {
        match self {
            Self::FrontendTlsHandshake => Some(TlsErrorSide::Frontend),
            Self::BackendTlsHandshake | Self::BackendDtlsHandshake => Some(TlsErrorSide::Backend),
            Self::RejectedByPlugin | Self::NoHealthyTargets => None,
        }
    }

    /// `true` when the failure is attributable to the client (or to a
    /// gateway-policy decision applied to the client request);
    /// `false` when it represents a backend-side failure that the client did
    /// not cause.
    ///
    /// Used by the disconnect-cause mappers to pick
    /// [`crate::plugins::DisconnectCause::RecvError`] vs.
    /// [`crate::plugins::DisconnectCause::BackendError`] in lockstep with the
    /// direction-attribution helper [`Self::direction`].
    pub fn is_client_side(self) -> bool {
        // TLS handshake failures derive their side from `tls_side()` so the
        // two methods can never disagree.
        if let Some(side) = self.tls_side() {
            return matches!(side, TlsErrorSide::Frontend);
        }
        matches!(self, Self::RejectedByPlugin)
    }

    /// Direction attribution for [`crate::plugins::StreamTransactionSummary::disconnect_direction`].
    ///
    /// Frontend-side failures classify as `ClientToBackend` (the client half
    /// of the relay is the originator). Backend-side failures classify as
    /// `BackendToClient` (the backend half is the originator).
    pub fn direction(self) -> crate::plugins::Direction {
        if self.is_client_side() {
            crate::plugins::Direction::ClientToBackend
        } else {
            crate::plugins::Direction::BackendToClient
        }
    }

    /// Static prefix string emitted by [`StreamSetupError`]'s Display impl.
    ///
    /// Returns the legacy `STREAM_ERR_*` constant declared in
    /// [`crate::proxy::tcp_proxy`]/[`crate::proxy::udp_proxy`] — log
    /// consumers grep on this exact wording, so the constants and the
    /// typed prefix are wired through the same source of truth. New code
    /// SHOULD walk the typed [`StreamSetupKind`] via downcast rather than
    /// match on this string; the prefix exists solely for log-pipeline
    /// stability.
    pub fn prefix(self) -> &'static str {
        match self {
            Self::FrontendTlsHandshake => {
                crate::proxy::tcp_proxy::STREAM_ERR_FRONTEND_TLS_HANDSHAKE_FAILED
            }
            Self::BackendTlsHandshake => {
                crate::proxy::tcp_proxy::STREAM_ERR_BACKEND_TLS_HANDSHAKE_FAILED
            }
            Self::BackendDtlsHandshake => {
                crate::proxy::udp_proxy::STREAM_ERR_BACKEND_DTLS_HANDSHAKE_FAILED
            }
            Self::RejectedByPlugin => crate::proxy::tcp_proxy::STREAM_ERR_REJECTED_BY_PLUGIN,
            Self::NoHealthyTargets => crate::proxy::tcp_proxy::STREAM_ERR_NO_HEALTHY_TARGETS,
        }
    }
}

/// Typed error for stream-family setup-phase failures.
///
/// Construction sites in [`crate::proxy::tcp_proxy`] and
/// [`crate::proxy::udp_proxy`] return `StreamSetupError` (boxed into
/// `anyhow::Error` via `into()`) instead of building a bare `anyhow!()`. The
/// disconnect-cause mappers downcast the chain to read the typed
/// [`StreamSetupKind`].
///
/// The wrapper preserves the original cause via `source()` so error chain
/// consumers (logging, port-exhaustion detection in
/// [`crate::retry::is_port_exhaustion`]) keep working.
#[derive(Debug)]
pub struct StreamSetupError {
    /// Typed kind. Carries enough information for cause mappers to decide
    /// `DisconnectCause` and `Direction` without inspecting the message.
    pub kind: StreamSetupKind,
    /// Free-form context for log readers — typically `format!("{} to {addr}: {err}", kind.prefix())`.
    /// Display is `{message}` (the prefix is already embedded by builders).
    pub message: String,
    /// Optional underlying cause. Set when the error wraps an `io::Error`,
    /// `rustls::Error`, etc. Walked by [`crate::retry::is_port_exhaustion`]
    /// and [`crate::retry::classify_boxed_error`].
    pub source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl StreamSetupError {
    /// Build an error whose Display is `"{prefix} {detail}"` — the canonical
    /// shape used at every legacy `anyhow!()` construction site.
    pub fn new(kind: StreamSetupKind, detail: impl fmt::Display) -> Self {
        Self {
            kind,
            message: format!("{} {}", kind.prefix(), detail),
            source: None,
        }
    }

    /// Like [`Self::new`] but attaches a typed source for chain-walkers.
    pub fn with_source<E>(kind: StreamSetupKind, detail: impl fmt::Display, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            message: format!("{} {}", kind.prefix(), detail),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for StreamSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StreamSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|s| s as &dyn std::error::Error)
    }
}

/// Walk an [`anyhow::Error`] source chain and return the first
/// [`StreamSetupError`] found, if any.
///
/// Cause mappers call this to discover typed kind information attached at
/// construction time. Returns `None` for errors that pre-date the typed
/// infrastructure or for chains that wrap a non-stream-setup error type
/// (raw `io::Error`, `rustls::Error`, etc.).
pub fn find_stream_setup_error(error: &anyhow::Error) -> Option<&StreamSetupError> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<StreamSetupError>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_side_partitions_kinds_correctly() {
        assert_eq!(
            StreamSetupKind::FrontendTlsHandshake.tls_side(),
            Some(TlsErrorSide::Frontend)
        );
        assert_eq!(
            StreamSetupKind::BackendTlsHandshake.tls_side(),
            Some(TlsErrorSide::Backend)
        );
        assert_eq!(
            StreamSetupKind::BackendDtlsHandshake.tls_side(),
            Some(TlsErrorSide::Backend)
        );
        assert_eq!(StreamSetupKind::RejectedByPlugin.tls_side(), None);
        assert_eq!(StreamSetupKind::NoHealthyTargets.tls_side(), None);
    }

    #[test]
    fn is_client_side_groups_match_disconnect_cause_intent() {
        // Client-side: anything the client did or that gateway policy applied
        // to the client request. RecvError in DisconnectCause terms.
        for kind in [
            StreamSetupKind::FrontendTlsHandshake,
            StreamSetupKind::RejectedByPlugin,
        ] {
            assert!(
                kind.is_client_side(),
                "{kind:?} should be client-side (RecvError-mapped)"
            );
        }
        // Backend-side: backend setup or LB selection failures.
        for kind in [
            StreamSetupKind::BackendTlsHandshake,
            StreamSetupKind::BackendDtlsHandshake,
            StreamSetupKind::NoHealthyTargets,
        ] {
            assert!(
                !kind.is_client_side(),
                "{kind:?} should be backend-side (BackendError-mapped)"
            );
        }
    }

    #[test]
    fn prefix_matches_legacy_wording() {
        // Lock the user-visible prefix wording to literal values. If a
        // future refactor changes a constant in tcp_proxy/udp_proxy, this
        // test catches the log-format break before it ships.
        assert_eq!(
            StreamSetupKind::FrontendTlsHandshake.prefix(),
            "Frontend TLS handshake failed"
        );
        assert_eq!(
            StreamSetupKind::BackendTlsHandshake.prefix(),
            "Backend TLS handshake failed"
        );
        assert_eq!(
            StreamSetupKind::BackendDtlsHandshake.prefix(),
            "Backend DTLS handshake failed"
        );
        assert_eq!(
            StreamSetupKind::RejectedByPlugin.prefix(),
            "rejected by plugin"
        );
        assert_eq!(
            StreamSetupKind::NoHealthyTargets.prefix(),
            "No healthy targets"
        );
    }

    #[test]
    fn display_preserves_legacy_prefix() {
        // Operators and dashboards key off these prefixes — they MUST round-trip
        // unchanged through the typed error path.
        let err = StreamSetupError::new(
            StreamSetupKind::FrontendTlsHandshake,
            "from 1.2.3.4:5678: invalid certificate",
        );
        let displayed = format!("{}", err);
        assert!(
            displayed.starts_with("Frontend TLS handshake failed "),
            "expected legacy prefix in {displayed:?}"
        );
        assert!(displayed.contains("invalid certificate"));
    }

    #[test]
    fn source_chain_walks_through_typed_wrapper() {
        // A wrapped io::Error must remain reachable via std::error::Error::source
        // so is_port_exhaustion and classify_boxed_error continue to detect
        // typed io kinds inside the chain.
        let inner = std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "ECONNREFUSED 1.2.3.4",
        );
        let err = StreamSetupError::with_source(
            StreamSetupKind::BackendTlsHandshake,
            "to 1.2.3.4:443:",
            inner,
        );
        let chain_io: Option<&std::io::Error> =
            std::error::Error::source(&err).and_then(|s| s.downcast_ref::<std::io::Error>());
        assert!(
            chain_io.is_some(),
            "io::Error must be reachable via source()"
        );
        assert_eq!(
            chain_io.unwrap().kind(),
            std::io::ErrorKind::ConnectionRefused
        );
    }

    #[test]
    fn find_stream_setup_error_walks_anyhow_chain() {
        // Construction-site idiom: `Err(StreamSetupError::new(...).into())` boxes
        // into anyhow::Error. find_stream_setup_error must recover the typed
        // kind via downcast.
        let original: anyhow::Error =
            StreamSetupError::new(StreamSetupKind::NoHealthyTargets, "for upstream foo").into();
        let wrapped = original.context("dispatch failed");
        let recovered =
            find_stream_setup_error(&wrapped).expect("typed kind must survive .context()");
        assert_eq!(recovered.kind, StreamSetupKind::NoHealthyTargets);
    }

    #[test]
    fn find_stream_setup_error_returns_none_for_untyped_errors() {
        let plain: anyhow::Error = anyhow::anyhow!("nothing typed in this chain");
        assert!(find_stream_setup_error(&plain).is_none());
    }
}
