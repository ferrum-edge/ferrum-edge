//! Inbound PROXY protocol on the process-global HTTP/HTTPS proxy listeners
//! (issue #5768).
//!
//! An L4 load balancer (AWS NLB, GCP TCP/SSL proxy, HAProxy in TCP mode, …)
//! cannot add `X-Forwarded-For` to TLS it does not terminate, so it carries the
//! client address in a PROXY v1/v2 header written before any application byte.
//! `FERRUM_FRONTEND_PROXY_PROTOCOL_HTTP` / `FERRUM_FRONTEND_PROXY_PROTOCOL_HTTPS`
//! opt one listener into reading that header; the wire parser is the shared
//! stream-proxy one in [`crate::proxy::proxy_protocol`].
//!
//! # Contract
//!
//! - **Opt-in per listener.** A disabled listener carries no policy
//!   (`Option::None`), so its accept loop does no extra work, allocation, or
//!   syscall.
//! - **Required, never optional.** On an enabled listener every connection must
//!   come from a peer inside `FERRUM_FRONTEND_PROXY_PROTOCOL_TRUSTED_CIDRS` and
//!   must begin with an accepted PROXY header. An untrusted peer is dropped at
//!   accept, before any byte is read; a missing, malformed, oversized,
//!   wrong-version, or slow header closes the connection. Nothing is answered
//!   on the wire in either case.
//! - **Before TLS and HTTP.** The header is consumed from the raw TCP stream
//!   ahead of the TLS ClientHello (HTTPS) or the first HTTP byte (plaintext),
//!   bounded by [`FRONTEND_PROXY_PROTOCOL_HEADER_TIMEOUT_SECONDS`] and the
//!   parser's size caps (107-byte v1 line, 512-byte v2 address block).
//! - **Replaces the socket peer.** A `PROXY` command's source address becomes
//!   the connection's peer address for everything downstream: `socket_ip`, the
//!   `X-Forwarded-For` hop Ferrum appends, per-IP limits, IP plugins, and logs.
//!   `FERRUM_TRUSTED_PROXIES` is then evaluated against that address exactly as
//!   if the client had connected directly, so the load balancer's own address
//!   never makes a client-supplied `X-Forwarded-For` believable. A `LOCAL`
//!   command or `UNKNOWN`/`AF_UNSPEC`/`AF_UNIX` family (load-balancer health
//!   checks) keeps the load balancer's socket address.
//! - **TCP only.** HTTP/3 (QUIC) has no standard PROXY carriage and is never
//!   covered; neither are Gateway API listener ports or mesh listeners.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::AsyncRead;

use crate::config::env_config::{EnvConfig, FrontendProxyProtocolMode};
use crate::plugins::utils::log_sampling::warn_sampled;
use crate::proxy::client_ip::TrustedProxies;
use crate::proxy::proxy_protocol::{
    AcceptedProxyVersions, ProxyProtocolError, ProxyProtocolResult, read_proxy_header_accepting,
};

/// Env key of the load-balancer source allowlist.
pub const FRONTEND_PROXY_PROTOCOL_TRUSTED_CIDRS_KEY: &str =
    "FERRUM_FRONTEND_PROXY_PROTOCOL_TRUSTED_CIDRS";

/// Seconds a trusted peer has to deliver the complete PROXY header. Matches
/// the stream-proxy bound; the frontend TLS handshake timeout and the HTTP
/// header-read timeout start only after the header has been consumed.
pub const FRONTEND_PROXY_PROTOCOL_HEADER_TIMEOUT_SECONDS: u64 = 5;

/// Which process-global proxy listener a policy belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontendProxyListener {
    /// The plaintext `FERRUM_PROXY_HTTP_PORT` listener.
    Http,
    /// The TLS `FERRUM_PROXY_HTTPS_PORT` listener (H1/H2 over TCP only).
    Https,
}

impl FrontendProxyListener {
    /// The env key that enables PROXY protocol on this listener.
    pub fn mode_env_key(self) -> &'static str {
        match self {
            Self::Http => "FERRUM_FRONTEND_PROXY_PROTOCOL_HTTP",
            Self::Https => "FERRUM_FRONTEND_PROXY_PROTOCOL_HTTPS",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// Inbound PROXY protocol policies of the two process-global proxy listeners.
#[derive(Debug, Default)]
pub struct GlobalListenerPolicies {
    /// Policy for the plaintext `FERRUM_PROXY_HTTP_PORT` listener.
    pub http: Option<Arc<FrontendProxyProtocol>>,
    /// Policy for the TLS `FERRUM_PROXY_HTTPS_PORT` listener.
    pub https: Option<Arc<FrontendProxyProtocol>>,
}

/// Resolve both global listener policies from `env` (see
/// [`FrontendProxyProtocol::for_listener`]).
pub fn global_listener_policies(env: &EnvConfig) -> Result<GlobalListenerPolicies, String> {
    Ok(GlobalListenerPolicies {
        http: FrontendProxyProtocol::for_listener(env, FrontendProxyListener::Http)?,
        https: FrontendProxyProtocol::for_listener(env, FrontendProxyListener::Https)?,
    })
}

/// Resolved inbound PROXY protocol policy for one enabled listener.
#[derive(Debug)]
pub struct FrontendProxyProtocol {
    listener: FrontendProxyListener,
    accepted: AcceptedProxyVersions,
    trusted_sources: TrustedProxies,
}

impl FrontendProxyProtocol {
    /// Build the policy for `listener` from `env`, or `None` when the listener
    /// leaves PROXY protocol `off`.
    ///
    /// `EnvConfig` validation already refuses an enabled listener with an
    /// empty, malformed, or catch-all trusted list; the checks are repeated
    /// here so no caller can install a policy that trusts nobody or everybody.
    pub fn for_listener(
        env: &EnvConfig,
        listener: FrontendProxyListener,
    ) -> Result<Option<Arc<Self>>, String> {
        let mode = match listener {
            FrontendProxyListener::Http => env.frontend_proxy_protocol_http,
            FrontendProxyListener::Https => env.frontend_proxy_protocol_https,
        };
        let accepted = match mode {
            FrontendProxyProtocolMode::Off => return Ok(None),
            FrontendProxyProtocolMode::V1 => AcceptedProxyVersions::V1Only,
            FrontendProxyProtocolMode::V2 => AcceptedProxyVersions::V2Only,
            FrontendProxyProtocolMode::Auto => AcceptedProxyVersions::Any,
        };
        let raw = &env.frontend_proxy_protocol_trusted_cidrs;
        let trusted_sources =
            TrustedProxies::parse_strict(raw, FRONTEND_PROXY_PROTOCOL_TRUSTED_CIDRS_KEY)?;
        if trusted_sources.is_empty() {
            return Err(format!(
                "{} enables inbound PROXY protocol but {FRONTEND_PROXY_PROTOCOL_TRUSTED_CIDRS_KEY} \
                 is empty",
                listener.mode_env_key()
            ));
        }
        if TrustedProxies::cidr_list_permits_all(raw) {
            return Err(format!(
                "{FRONTEND_PROXY_PROTOCOL_TRUSTED_CIDRS_KEY} admits every source address of an \
                 address family"
            ));
        }
        tracing::info!(
            listener = listener.label(),
            mode = %mode,
            trusted_source_entries = trusted_sources.len(),
            "Inbound PROXY protocol is required on the {} proxy listener",
            listener.label()
        );
        if listener == FrontendProxyListener::Https && env.enable_http3 {
            tracing::warn!(
                "FERRUM_FRONTEND_PROXY_PROTOCOL_HTTPS covers HTTP/1.1 and HTTP/2 over TCP only; \
                 the HTTP/3 (QUIC) listener on the same port never reads a PROXY header and \
                 keeps using the UDP socket peer as the client address"
            );
        }
        Ok(Some(Arc::new(Self {
            listener,
            accepted,
            trusted_sources,
        })))
    }

    /// Whether `peer` (the canonicalized socket peer) may send a PROXY header
    /// on this listener. A `false` result means the connection must be dropped.
    #[inline]
    pub fn trusts(&self, peer: &IpAddr) -> bool {
        self.trusted_sources.contains(peer)
    }

    /// Consume the PROXY header from `stream` and return the address the rest
    /// of the connection must treat as its peer.
    ///
    /// `peer` is the canonicalized socket peer; it is returned unchanged for a
    /// header that carries no client address (`LOCAL`, `UNKNOWN`, `AF_UNSPEC`,
    /// `AF_UNIX`). A forwarded IPv4-mapped IPv6 source is folded to native IPv4
    /// so it matches the principal a direct connection would produce. Any error
    /// means the caller must close the connection without answering.
    pub async fn read_client_addr<R>(
        &self,
        stream: &mut R,
        peer: SocketAddr,
    ) -> Result<SocketAddr, ProxyProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let header = read_proxy_header_accepting(
            stream,
            Some(FRONTEND_PROXY_PROTOCOL_HEADER_TIMEOUT_SECONDS),
            self.accepted,
        )
        .await?;
        Ok(match header {
            ProxyProtocolResult::Forwarded { src, .. } => {
                crate::util::client_identity::canonical_socket_addr(src)
            }
            ProxyProtocolResult::NoAddress => peer,
        })
    }

    /// Record a connection dropped because its socket peer is not a trusted
    /// load balancer. Sampled: a direct-connect flood cannot flood the log.
    pub fn log_untrusted_peer(&self, peer: &SocketAddr) {
        warn_sampled!(
            listener = self.listener.label(),
            peer = %peer.ip(),
            "Closing connection: inbound PROXY protocol is enabled on this listener but the \
             socket peer is not in FERRUM_FRONTEND_PROXY_PROTOCOL_TRUSTED_CIDRS"
        );
    }

    /// Record a connection closed because it did not start with an accepted
    /// PROXY header. Sampled like [`Self::log_untrusted_peer`].
    pub fn log_invalid_header(&self, peer: &SocketAddr, error: &ProxyProtocolError) {
        warn_sampled!(
            listener = self.listener.label(),
            peer = %peer.ip(),
            error = %error,
            "Closing connection: inbound PROXY protocol is required on this listener but the \
             connection did not start with an accepted PROXY header"
        );
    }
}
