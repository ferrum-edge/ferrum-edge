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
    /// The client reset the connection or the socket reported a transport
    /// error while the fault-injection plugin was still delaying admission.
    /// Client-side; used to cancel the delay without retaining the connection
    /// task. A graceful read-half close is not classified as a disconnect.
    ClientDisconnectedDuringAdmission,
    /// Backend hostname could not be resolved during stream setup. Backend-side
    /// and pre-wire: no SYN was sent. Maps to
    /// [`crate::retry::ErrorClass::DnsLookupError`] so TCP/UDP DNS failures
    /// grep the same class as HTTP/gRPC.
    DnsLookup,
    /// Load balancer returned no candidate for the configured upstream.
    /// Backend-side — the pool is empty, the subset is empty, or no backend
    /// shares the session destination's address family.
    ///
    /// Distinct from [`Self::CircuitBreakerOpen`]: this kind fires from the LB
    /// selection layer when no candidate exists at all. An upstream whose
    /// targets are all failing active health checks still selects a target
    /// via the shared all-unhealthy fallback (`docs/load_balancing.md`); that
    /// degraded dial is a later connect failure, not this kind.
    NoHealthyTargets,
    /// Per-proxy circuit breaker is open — the failure rate against the
    /// upstream exceeded the configured threshold and new connection
    /// attempts are short-circuited until the cooldown window elapses.
    /// Backend-side: the gateway is shedding traffic away from a known-bad
    /// upstream, not rejecting the client.
    CircuitBreakerOpen,
    /// DestinationRule `connectionPool.tcp.maxConnections` cap was already
    /// reached for the resolved backend target. Backend-side: the upstream
    /// is configured with a hard inflight ceiling and the gateway is
    /// applying the operator's intent. Distinct from `CircuitBreakerOpen`
    /// (which is a failure-rate gate) and from runtime port exhaustion
    /// (which is a host-level resource exhaustion).
    BackendMaxConnectionsExceeded,
    /// The configured stream-family policy is recognized, but this path cannot
    /// apply it correctly yet. Backend-side: the gateway is refusing to route
    /// with different semantics than the operator configured.
    UnsupportedStreamPolicy,
    /// The authorization lifetime of the credential that admitted this stream
    /// elapsed during post-admission setup (DNS, retry backoff, backend
    /// connect/handshake, outbound PROXY framing, inspected-prefix forwarding),
    /// before any backend or application byte was written (issue #3816).
    ///
    /// Client-side: like [`Self::RejectedByPlugin`], this is a gateway-policy
    /// decision applied to the client's own credential, not a backend fault, so
    /// it must stay health-neutral — it never records a circuit-breaker or
    /// passive-health failure against the upstream.
    AuthorizationExpired,
    /// An operator withdrew the frontend client-certificate trust decision this
    /// stream was admitted under (a CRL now revokes the peer's certificate, or
    /// its issuing CA left the client-CA bundle) while post-admission setup was
    /// still running — DNS, retry backoff, backend connect/handshake, outbound
    /// PROXY framing, or the inspected-prefix forward (issue #3857).
    ///
    /// Distinct from [`Self::AuthorizationExpired`], which is the admitted
    /// credential reaching its own `notAfter`: the two are independent,
    /// earliest-wins termination causes.
    ///
    /// Client-side and health-neutral for the same reason: withdrawing a trust
    /// root is the operator's own local authorization decision, not evidence
    /// about the upstream, so it never records a circuit-breaker or
    /// passive-health failure against it.
    ClientTrustWithdrawn,
    /// Opaque-TLS SNI listener admission refused the connection before any
    /// backend was selected, dialed, health-scored, or breaker-charged
    /// (issue #4407). Covers not-TLS on an SNI port, ClientHello timeout /
    /// overflow / EOF / truncation / malformation / unrepresentable
    /// `server_name`, peek I/O failure, and a valid hello whose SNI matches
    /// no route (and no catch-all). Gateway-local: `is_client_side` is true
    /// so the class stays health-neutral, but [`Self::direction`] is
    /// `Unknown` because no backend leg existed, and
    /// [`Self::disconnect_cause`] is `GatewayPolicy` rather than `RecvError`.
    SniAdmissionRefused,
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
            Self::RejectedByPlugin
            | Self::ClientDisconnectedDuringAdmission
            | Self::DnsLookup
            | Self::NoHealthyTargets
            | Self::CircuitBreakerOpen
            | Self::BackendMaxConnectionsExceeded
            | Self::UnsupportedStreamPolicy
            | Self::AuthorizationExpired
            | Self::ClientTrustWithdrawn
            | Self::SniAdmissionRefused => None,
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
        matches!(
            self,
            Self::RejectedByPlugin
                | Self::ClientDisconnectedDuringAdmission
                | Self::AuthorizationExpired
                | Self::ClientTrustWithdrawn
                | Self::SniAdmissionRefused
        )
    }

    /// Direction attribution for [`crate::plugins::StreamTransactionSummary::disconnect_direction`].
    ///
    /// Frontend-side failures classify as `ClientToBackend` (the client half
    /// of the relay is the originator). Backend-side failures classify as
    /// `BackendToClient` (the backend half is the originator). Opaque-TLS
    /// SNI admission refusals classify as `Unknown`: no backend leg existed,
    /// so attributing either copy direction would invent a socket that was
    /// never opened (issue #4407).
    pub fn direction(self) -> crate::plugins::Direction {
        if matches!(self, Self::SniAdmissionRefused) {
            return crate::plugins::Direction::Unknown;
        }
        if self.is_client_side() {
            crate::plugins::Direction::ClientToBackend
        } else {
            crate::plugins::Direction::BackendToClient
        }
    }

    /// Cause attribution for [`crate::plugins::StreamTransactionSummary::disconnect_cause`].
    ///
    /// Most client-side kinds map to `RecvError` and most backend-side kinds
    /// to `BackendError`. [`Self::SniAdmissionRefused`] is a gateway policy
    /// decision with no backend, so it maps to `GatewayPolicy` rather than
    /// overloading `RecvError` (a client-socket read) or `BackendError`.
    pub fn disconnect_cause(self) -> crate::plugins::DisconnectCause {
        if matches!(self, Self::SniAdmissionRefused) {
            return crate::plugins::DisconnectCause::GatewayPolicy;
        }
        if self.is_client_side() {
            crate::plugins::DisconnectCause::RecvError
        } else {
            crate::plugins::DisconnectCause::BackendError
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
            Self::ClientDisconnectedDuringAdmission => {
                crate::proxy::tcp_proxy::STREAM_ERR_CLIENT_DISCONNECTED_DURING_ADMISSION
            }
            Self::DnsLookup => crate::proxy::tcp_proxy::STREAM_ERR_DNS_LOOKUP_FAILED,
            Self::NoHealthyTargets => crate::proxy::tcp_proxy::STREAM_ERR_NO_HEALTHY_TARGETS,
            Self::CircuitBreakerOpen => crate::proxy::tcp_proxy::STREAM_ERR_CIRCUIT_BREAKER_OPEN,
            Self::BackendMaxConnectionsExceeded => {
                crate::proxy::tcp_proxy::STREAM_ERR_BACKEND_MAX_CONNECTIONS
            }
            Self::UnsupportedStreamPolicy => {
                crate::proxy::tcp_proxy::STREAM_ERR_UNSUPPORTED_STREAM_POLICY
            }
            Self::AuthorizationExpired => crate::proxy::tcp_proxy::STREAM_ERR_AUTHORIZATION_EXPIRED,
            Self::ClientTrustWithdrawn => {
                crate::proxy::tcp_proxy::STREAM_ERR_CLIENT_TRUST_WITHDRAWN
            }
            Self::SniAdmissionRefused => crate::proxy::tcp_proxy::STREAM_ERR_SNI_ADMISSION_REFUSED,
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
    /// Build an error whose Display is `"{prefix} {detail}"` (single-space
    /// separator) — the canonical shape used at construction sites whose
    /// legacy wording was `"{prefix} from {addr}: {err}"`,
    /// `"{prefix} to {addr}: {err}"`, `"Connection {prefix}"`,
    /// `"{prefix} for upstream {id}"`, etc. The caller's detail string
    /// owns whatever connector word follows the prefix.
    ///
    /// For sites whose legacy emit was `"{prefix}: {detail}"` (no
    /// connector word — bare colon-and-space), use
    /// [`Self::with_colon_detail`] instead so the byte-for-byte log
    /// wording is preserved.
    pub fn new(kind: StreamSetupKind, detail: impl fmt::Display) -> Self {
        Self {
            kind,
            message: format!("{} {}", kind.prefix(), detail),
            source: None,
        }
    }

    /// Build an error whose Display is `"{prefix}: {detail}"` (colon +
    /// single-space separator).
    ///
    /// Used at construction sites whose legacy `anyhow!()` emit was
    /// `"{}: {}"` directly — currently the two backend DTLS handshake
    /// sites in [`crate::proxy::udp_proxy`]. Calling [`Self::new`] there
    /// with a leading `":"` in the detail produced a stray space before
    /// the colon (`"Backend DTLS handshake failed : ..."`) which broke
    /// exact-match log pipelines keyed on the legacy wording.
    pub fn with_colon_detail(kind: StreamSetupKind, detail: impl fmt::Display) -> Self {
        Self {
            kind,
            message: format!("{}: {}", kind.prefix(), detail),
            source: None,
        }
    }

    /// Build an error whose Display is exactly `message`, with no prefix
    /// interpolation. Use when the production wording is already complete
    /// (the two opaque-TLS SNI admission strings, issue #4407).
    pub fn with_message(kind: StreamSetupKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
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

    /// Setup-phase DNS failure. Display is the legacy
    /// `"DNS resolution failed for {host}: {source}"` wording so log
    /// pipelines keyed on that prefix keep matching.
    ///
    /// Takes `anyhow::Error` because every stream DNS resolve site
    /// (`DnsCache::resolve_candidates`, `DnsCache::resolve`) returns one.
    /// The source is retained as a boxed chain link so
    /// the classifier's typed source walk can still reach the underlying typed
    /// cause.
    ///
    /// Prefer `stream_dns_setup_error`, which additionally refuses to type
    /// a gateway-side egress-policy denial as a name-resolution failure.
    pub fn dns_lookup(host: impl fmt::Display, source: anyhow::Error) -> Self {
        let kind = StreamSetupKind::DnsLookup;
        Self {
            kind,
            message: format!("{} for {host}: {source}", kind.prefix()),
            source: Some(source.into()),
        }
    }
}

/// Wrap a stream-setup DNS resolve failure in the correct taxonomy.
///
/// A resolve refused by the backend egress policy is a **gateway-side dispatch
/// decision**, not a name-resolution outcome: no query was answered and no
/// backend was consulted. It already classifies as
/// [`crate::retry::ErrorClass::DispatchPolicyRejected`] — non-retryable and
/// neutral to backend health — via the `"egress policy"` anchor in the
/// substring fallback. Typing it as [`StreamSetupKind::DnsLookup`] would take
/// precedence over that anchor in the typed walk and silently reclassify it as
/// `dns_lookup_error`, changing both its retryability and its backend-health
/// attribution.
///
/// So the denial keeps its untyped wording (byte-identical to the pre-typed
/// emit) and only genuine resolver failures become typed DNS setup errors.
pub(crate) fn stream_dns_setup_error(host: &str, source: anyhow::Error) -> anyhow::Error {
    if crate::dns::is_egress_policy_denial(&source) {
        return anyhow::anyhow!("DNS resolution failed for {host}: {source}");
    }
    StreamSetupError::dns_lookup(host, source).into()
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
        assert_eq!(
            StreamSetupKind::ClientDisconnectedDuringAdmission.tls_side(),
            None
        );
        assert_eq!(StreamSetupKind::DnsLookup.tls_side(), None);
        assert_eq!(StreamSetupKind::NoHealthyTargets.tls_side(), None);
        assert_eq!(StreamSetupKind::CircuitBreakerOpen.tls_side(), None);
        assert_eq!(
            StreamSetupKind::BackendMaxConnectionsExceeded.tls_side(),
            None
        );
        assert_eq!(StreamSetupKind::UnsupportedStreamPolicy.tls_side(), None);
        assert_eq!(StreamSetupKind::SniAdmissionRefused.tls_side(), None);
    }

    #[test]
    fn is_client_side_groups_match_disconnect_cause_intent() {
        // Client-side: anything the client did or that gateway policy applied
        // to the client request. RecvError in DisconnectCause terms.
        for kind in [
            StreamSetupKind::FrontendTlsHandshake,
            StreamSetupKind::RejectedByPlugin,
            StreamSetupKind::ClientDisconnectedDuringAdmission,
            StreamSetupKind::SniAdmissionRefused,
        ] {
            assert!(
                kind.is_client_side(),
                "{kind:?} should be client-side (health-neutral)"
            );
        }
        // Backend-side: backend setup or LB selection failures, plus
        // circuit-breaker rejects (the gateway is shedding traffic away
        // from a known-bad upstream — backend's fault, not the client's).
        for kind in [
            StreamSetupKind::BackendTlsHandshake,
            StreamSetupKind::BackendDtlsHandshake,
            StreamSetupKind::DnsLookup,
            StreamSetupKind::NoHealthyTargets,
            StreamSetupKind::CircuitBreakerOpen,
            StreamSetupKind::BackendMaxConnectionsExceeded,
            StreamSetupKind::UnsupportedStreamPolicy,
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
            StreamSetupKind::ClientDisconnectedDuringAdmission.prefix(),
            "client disconnected during plugin admission"
        );
        assert_eq!(StreamSetupKind::DnsLookup.prefix(), "DNS resolution failed");
        assert_eq!(
            StreamSetupKind::NoHealthyTargets.prefix(),
            "No healthy targets"
        );
        assert_eq!(
            StreamSetupKind::CircuitBreakerOpen.prefix(),
            "circuit breaker open"
        );
        assert_eq!(
            StreamSetupKind::BackendMaxConnectionsExceeded.prefix(),
            "Backend maxConnections reached"
        );
        assert_eq!(
            StreamSetupKind::UnsupportedStreamPolicy.prefix(),
            "Unsupported stream policy"
        );
        assert_eq!(
            StreamSetupKind::SniAdmissionRefused.prefix(),
            "SNI-routed stream listener"
        );
    }

    #[test]
    fn sni_admission_refused_is_gateway_policy_with_unknown_direction() {
        let kind = StreamSetupKind::SniAdmissionRefused;
        assert!(kind.is_client_side());
        assert_eq!(kind.direction(), crate::plugins::Direction::Unknown);
        assert_eq!(
            kind.disconnect_cause(),
            crate::plugins::DisconnectCause::GatewayPolicy
        );
        let err = StreamSetupError::with_message(
            kind,
            "SNI-routed stream listener on port 21582 refused connection (not_tls)",
        );
        assert_eq!(
            format!("{err}"),
            "SNI-routed stream listener on port 21582 refused connection (not_tls)"
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
    fn display_byte_for_byte_matches_legacy_wording() {
        // Lock the EXACT wording each constructor produces so log pipelines
        // keyed on the legacy `anyhow!()` strings keep matching:
        //
        //   `anyhow!("{} from {}: {}", STREAM_ERR_FRONTEND_TLS_HANDSHAKE_FAILED, addr, e)`
        //   → `StreamSetupError::new(FrontendTlsHandshake, "from <addr>: <err>")`
        //   produces `"Frontend TLS handshake failed from <addr>: <err>"`.
        //
        //   `anyhow!("{}: {}", STREAM_ERR_BACKEND_DTLS_HANDSHAKE_FAILED, e)`
        //   → `StreamSetupError::with_colon_detail(BackendDtlsHandshake, "<err>")`
        //   produces `"Backend DTLS handshake failed: <err>"`.
        //
        // Without `with_colon_detail`, passing `format!(": {e}")` to `new`
        // would produce a stray space (`"... failed : ..."`) and break
        // exact-match log pipelines.
        let frontend = StreamSetupError::new(
            StreamSetupKind::FrontendTlsHandshake,
            "from 1.2.3.4:5678: bad cert",
        );
        assert_eq!(
            format!("{frontend}"),
            "Frontend TLS handshake failed from 1.2.3.4:5678: bad cert"
        );

        let backend_tcp = StreamSetupError::new(
            StreamSetupKind::BackendTlsHandshake,
            "to 10.0.0.1:443: alert: bad_certificate",
        );
        assert_eq!(
            format!("{backend_tcp}"),
            "Backend TLS handshake failed to 10.0.0.1:443: alert: bad_certificate"
        );

        let backend_dtls = StreamSetupError::with_colon_detail(
            StreamSetupKind::BackendDtlsHandshake,
            "alert: bad_certificate",
        );
        assert_eq!(
            format!("{backend_dtls}"),
            "Backend DTLS handshake failed: alert: bad_certificate"
        );
        // Critical: NO stray space before the colon.
        assert!(
            !format!("{backend_dtls}").contains("failed :"),
            "DTLS legacy wording must use ': ' (no preceding space)"
        );

        let inner = anyhow::Error::from(std::io::Error::other(
            "DNS resolution returned no addresses for backend.local",
        ));
        let dns = StreamSetupError::dns_lookup("backend.local", inner);
        let displayed = format!("{dns}");
        assert!(
            displayed.starts_with("DNS resolution failed for backend.local: "),
            "expected legacy DNS prefix in {displayed:?}"
        );
        assert!(displayed.contains("DNS resolution returned no addresses"));
        assert_eq!(dns.kind, StreamSetupKind::DnsLookup);
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
